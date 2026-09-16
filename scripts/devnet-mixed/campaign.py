#!/usr/bin/env python3
"""Run the isolated mixed-node campaign, retaining evidence even after a failure."""
import argparse
import datetime
import gzip
import hashlib
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import time
import urllib.error

from artifacts import read_members, write_archive
from smoke import ROOT, HERE, WORK, URLS, PK, api, tips, wait_for as poll_until

RESULTS = ROOT / 'test-vectors/ergo-sigma/cost-ledger/results'
VECTORS = RESULTS.parent
CAP = 37509


def require_peers():
    try:
        counts = {node: len(api(node, '/peers/connected')) for node in URLS}
    except (OSError, ValueError) as error:
        raise RuntimeError('P2P health unavailable; campaign aborted') from error
    if any(count < 1 for count in counts.values()):
        raise RuntimeError('P2P disconnected; campaign aborted: ' + str(counts))


def wait_for(callback, description, timeout=180):
    def connected_callback():
        require_peers()
        return callback()
    return poll_until(connected_callback, description, timeout)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def observations():
    require_peers()
    return {node: api(node, '/info') for node in URLS}


def commitment(info):
    return {key: info[key] for key in ('fullHeight', 'bestFullHeaderId', 'stateRoot')}


def post(node, path, value):
    try:
        return {'http_status': 200, 'response': api(node, path, value)}
    except urllib.error.HTTPError as error:
        return {'http_status': error.code, 'response': error.read().decode()}


def select_workload():
    source = VECTORS / 'blocks/f-v6-devnet.json.gz'
    fixture = json.loads(gzip.decompress(source.read_bytes()))
    box = bytes.fromhex(fixture['parent_boxes_hex'][0])
    def vlq(offset):
        value = shift = 0
        while True:
            byte = box[offset]
            offset += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value, offset
            shift += 7
    _, start = vlq(0)  # value precedes the self-delimiting v3 ErgoTree
    if not box[start] & 8:
        raise RuntimeError('family-f input must have a sized ErgoTree')
    size, payload = vlq(start + 1)
    selected = [{'source': str(source.relative_to(ROOT)), 'case': 'f-v6-devnet',
                 'tree_hex': box[start:payload + size].hex(), 'sha256': sha(source)}]
    for name in ('coll-flatMap', 'coll-zip', 'global-xor'):
        source = VECTORS / f'fixtures/method/{name}.json.gz'
        fixture = json.loads(gzip.decompress(source.read_bytes()))
        eligible = [case for case in fixture['cases'] if case['expected']['verdict'] == 'Accept'
                    and case['request']['ctx_ext_hex'] == '00'
                    and not case['request']['proof_hex']
                    and case['expected']['total_block_cost'] <= 1500]
        case = max(eligible, key=lambda case: case['expected']['total_block_cost'])
        selected.append({'source': str(source.relative_to(ROOT)), 'case': case['name'],
                         'tree_hex': case['request']['tree_hex'], 'sha256': sha(source),
                         'l2_expected': case['expected']})
    return selected


def environment():
    return os.environ | {'SCALA_CONFIG': str(WORK / 'campaign-scala-node.conf'),
                         'RUST_CONFIG': str(WORK / 'campaign-rust-node.toml'),
                         'CAMPAIGN_CLASSPATH': str(WORK / 'campaign-classes')}


def prepare():
    WORK.mkdir(exist_ok=True)
    (WORK / 'campaign-scala').mkdir(exist_ok=True)
    scala = (HERE / 'scala-node.conf').read_text().replace('include "genesis.conf"',
        f'include "{HERE}/genesis.conf"').replace('.work/scala"', '.work/campaign-scala"')
    rust = (HERE / 'rust-node.toml').read_text().replace('.work/rust"', '.work/campaign-rust"')
    write_config = ((WORK / 'campaign-scala-node.conf', scala),
                    (WORK / 'campaign-rust-node.toml', rust + '\n[chain]\ndevnet_max_block_cost = 37509\n'))
    for path, contents in write_config:
        path.write_text(contents)
    cp = (ROOT / 'scripts/jvm_block_oracle/.work/classpath').read_text().strip()
    with (WORK / 'campaign-compile.log').open('w') as log:
        subprocess.run(['scala-cli', 'compile', str(HERE / 'CampaignParameters.scala'),
            '--server=false', '--suppress-outdated-dependency-warning', '--scala', '2.12.20',
            '--classpath', cp, '-d', str(WORK / 'campaign-classes')], cwd=ROOT,
            stdout=log, stderr=subprocess.STDOUT, check=True)


def build(name, *options):
    output = WORK / (name + '.json')
    with (WORK / (name + '-build.log')).open('w') as log:
        process = subprocess.Popen([sys.executable, str(HERE / 'build-block.py'), '--live', *map(str, options),
                        str(output)], cwd=ROOT, env=environment(), stdout=log,
                        stderr=subprocess.STDOUT, start_new_session=True)
        try:
            while process.poll() is None:
                require_peers()
                time.sleep(0.25)
            if process.returncode:
                raise RuntimeError(f'block builder failed ({process.returncode}); see {log.name}')
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait()
            raise
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--direction', required=True, choices=('scala-mines', 'rust-mines'))
    args = parser.parse_args()
    direction = args.direction
    miner = direction.split('-')[0]
    started = datetime.datetime.now(datetime.timezone.utc)
    output = RESULTS / f'l6-{started.date()}.json'
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    selected = select_workload()
    run = {'direction': direction, 'status': 'RUNNING', 'selected': len(selected) + 3,
           'executed': 0, 'skipped': 0, 'skipped_items': [], 'failed': 0, 'warmup': [], 'workload': [], 'injections': [],
           'manifest': {'scala': {'ergo_version': '6.0.5', 'sigmastate_version': '6.0.6',
               'node_app_version': '6.0.5', 'source_shas': {
                   'ergo': '5528ef569a41ebccbc8658212e6ee3c97d990b96',
                   'sigmastate': 'ab0b15ceb9d34f2ccd6e68e3e2a8aa27cd16a042'}},
             'scala_launch_override': {'source': 'scripts/devnet-mixed/CampaignParameters.scala', 'parameters': {'4': CAP}, 'scope': 'devnet60 genesis only; original validation and cost code'},
             'rust': {'git_sha': revision, 'features': ['default'],
                      'toolchain': subprocess.check_output(['rustc', '--version'], text=True).strip(),
                      'working_diff_sha256': hashlib.sha256(subprocess.check_output(['git', 'diff', 'HEAD'], cwd=ROOT)).hexdigest()},
             'tool': {'script': 'scripts/devnet-mixed/campaign.sh', 'git_sha': revision,
                      'scala_cli_version': subprocess.check_output(['scala-cli', 'version', '--cli'], text=True).strip(),
                      'jvm': subprocess.run(['java', '-version'], capture_output=True, text=True).stderr.strip()},
             'run': {'command': f'scripts/devnet-mixed/campaign.sh --direction {direction}',
                     'seeds': {'miner_secret_scalar': 1}, 'timestamp': started.isoformat()},
             'evidence': {item['source']: item['sha256'] for item in selected}},
           'selection': selected}
    results = json.loads(output.read_text()) if output.exists() else {'runs': []}
    if results.get('divergence') or any(item['status'] == 'DIVERGENT' for item in results['runs']):
        raise RuntimeError('recorded divergence: resolve the ledger row before starting a fresh campaign')
    if any(item['direction'] == direction and item['status'] == 'PASS' for item in results['runs']):
        raise RuntimeError('successful direction already recorded; preserve its result and use a fresh campaign')
    results['runs'].append(run)
    archive_path = RESULTS / f'l6-{started.date()}-artifacts.tar.gz'
    members = read_members(archive_path)
    def save():
        # The shared archive grows across attempts; refresh every enclosing digest.
        for item in results['runs']:
            if archive_path.exists():
                item['manifest']['evidence'][str(archive_path.relative_to(ROOT))] = sha(archive_path)
            item.pop('payload_sha256_excluding_this_field', None)
            item['payload_sha256_excluding_this_field'] = hashlib.sha256(
                json.dumps(item, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        write(output, results)
    def archive(path):
        member = f'l6-{started.date()}-artifacts/resumed-attempt-{len(results["runs"])}-{path.name}.gz'
        member = str(RESULTS.relative_to(ROOT) / member)
        payload = path.read_bytes()
        compressed = gzip.compress(payload, mtime=0)
        members[member] = compressed
        write_archive(archive_path, members)
        name = str(archive_path.relative_to(ROOT)) + '#' + member
        digest = hashlib.sha256(compressed).hexdigest()
        run['manifest']['evidence'][name] = digest
        return {'path': name, 'sha256': digest, 'uncompressed_sha256': hashlib.sha256(payload).hexdigest()}
    def retain_build(path):
        return {suffix or 'block': archive(Path(str(path) + suffix))
                for suffix in ('', '.oracle.json', '.transactions.json')}
    def inject(block, label, expected='Accept', oracle=None):
        before = observations()
        record = {'case': label, 'block_id': block['header']['id'], 'before': before,
                  'expected': expected, 'oracle': oracle, 'submissions': {}}
        run['injections'].append(record)
        offsets = {n: (WORK / (n + '.log')).stat().st_size for n in URLS}
        for node in URLS:
            record['submissions'][node] = post(node, '/blocks', block)
            save()
        if expected == 'Accept':
            try:
                after = wait_for(lambda: tips(block['header']['height']), label, timeout=30)
            except RuntimeError:
                after = observations()
        else:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                require_peers()
                time.sleep(0.25)
            after = observations()
        record['after'] = after
        record['verdicts'] = {n: 'Accept' if i['bestFullHeaderId'] == block['header']['id']
                              else 'Unchanged' if commitment(i) == commitment(before[n])
                              else 'UnexpectedState' for n, i in after.items()}
        record['validation_logs'] = {}
        for node in URLS:
            with (WORK / (node + '.log')).open('rb') as log:
                log.seek(offsets[node])
                record['validation_logs'][node] = log.read().decode(errors='replace')
        save()
        expected_state = 'Accept' if expected == 'Accept' else 'Unchanged'
        if any(verdict != expected_state for verdict in record['verdicts'].values()):
            raise RuntimeError('DIVERGENCE: ' + label + ' ' + str(record['verdicts']))
        if label == 'funding' and 'EmissionInvariant' in record['validation_logs']['rust']:
            raise RuntimeError('DIVERGENCE: Rust emission discovery failed after the accepted funding block')
        return record
    try:
        subprocess.run([str(HERE / 'stop.sh')], check=True)
        for node in URLS:
            log = WORK / (node + '.log')
            if log.exists():
                archive(log)
                log.write_text('')
        prepare()
        subprocess.run([str(HERE / 'start.sh')], env=environment(), check=True)
        def starting_tip():
            initial = observations()
            if any(i.get('stateRoot') is None for i in initial.values()):
                return None
            return tips(initial['scala']['fullHeight'] or 0)
        initial = wait_for(starting_tip, 'both initialized nodes share the starting tip')
        height = initial['scala']['fullHeight'] or 0
        if any(i['parameters']['maxBlockCost'] != CAP for i in initial.values()):
            raise RuntimeError('both nodes must use the campaign genesis cost cap')
        run['manifest']['rust']['binary_sha256'] = sha(Path('/proc') / (WORK / 'rust.pid').read_text().strip() / 'exe')
        run['manifest']['context'] = {'network': 'private devnet / devnet60',
            'chain_id': 'sha256:' + sha(HERE / 'genesis.conf'),
            'height_range': [height, None], 'activated_script_version': 3, 'block_version': 4,
            'voted_params': {str(k): initial['scala']['parameters'][v] for k, v in
                            ((4, 'maxBlockCost'), (5, 'tokenAccessCost'), (6, 'inputCost'), (7, 'dataInputCost'), (8, 'outputCost'))}}
        wait_for(lambda: all(api(n, '/peers/connected') for n in URLS), 'mixed-devnet P2P handshake')
        for path in (HERE / 'artifacts.py', HERE / 'campaign.py', HERE / 'campaign.sh', HERE / 'BuildBlock.scala',
                     HERE / 'CampaignTransactions.scala', HERE / 'CampaignParameters.scala', HERE / 'build-block.py',
                     HERE / 'lifecycle.py', HERE / 'genesis.conf', WORK / 'campaign-scala-node.conf', WORK / 'campaign-rust-node.toml'):
            run['manifest']['evidence'][str(path.relative_to(ROOT))] = sha(path)
        if height < 720:
            path = build(direction + '-warmup', '--count', 720 - height)
            blocks = json.loads(path.read_text())
            if isinstance(blocks, dict):
                blocks = [blocks]
            run['warmup_artifact'] = archive(path)
            for block in blocks:
                for node in URLS:
                    response = post(node, '/blocks', block)
                    if response['http_status'] != 200:
                        raise RuntimeError('warmup submission failed: ' + str(response))
                after = wait_for(lambda: tips(block['header']['height']), 'warmup', timeout=30)
                run['warmup'].append({n: commitment(i) for n, i in after.items()})
                if block['header']['height'] % 25 == 0:
                    print(f'warmup height {block["header"]["height"]}', flush=True)
                save()
        else:
            run['maturity'] = {'starting_height': height, 'required_height': 720}
            prior = [item for item in results['runs'][:-1] if item['status'] == 'PASS' and item['warmup']]
            if prior:
                run['maturity']['warmup_artifact'] = prior[-1]['warmup_artifact']
        trees = WORK / (direction + '-trees.json')
        write(trees, [item['tree_hex'] for item in selected])
        fund_path = build(direction + '-fund', '--campaign-stage', 'fund', '--workload-trees', trees)
        funding_block = json.loads(fund_path.read_text())
        run['funding_artifacts'] = retain_build(fund_path)
        inject(funding_block, 'funding')
        funding = WORK / (direction + '-funding-transaction.json')
        write(funding, funding_block['blockTransactions']['transactions'][0])
        for index, item in enumerate(selected):
            path = build(direction + f'-workload-{index}', '--campaign-stage', 'workload',
                         '--funding', funding, '--workload-index', index)
            artifacts = retain_build(path)
            transaction = json.loads(Path(str(path) + '.transactions.json').read_text())[0]
            before = observations()
            pending = {'artifacts': artifacts, 'selection': item, 'transaction_id': transaction['id'],
                       'before': before, 'oracle': json.loads(Path(str(path) + '.oracle.json').read_text())}
            run['workload'].append(pending)
            run['executed'] += 1
            save()
            previous_candidate = api(miner, '/mining/candidate')
            response = post(miner, '/transactions', transaction)
            if response['http_status'] != 200:
                raise RuntimeError('workload transaction admission failed: ' + str(response))
            height = before[miner]['fullHeight'] + 1
            if miner == 'scala':
                candidate = api(miner, '/mining/candidateWithTxs', [transaction])
                if candidate.get('h') != height:
                    raise RuntimeError('prioritized candidate has the wrong height')
            else:
                def refreshed_candidate():
                    candidate = api(miner, '/mining/candidate')
                    if candidate.get('h') == height and candidate['msg'] != previous_candidate['msg']:
                        return candidate
                    return None
                candidate = wait_for(refreshed_candidate, 'candidate rebuilt after workload admission')
            api(miner, '/mining/solution', {'pk': PK, 'w': PK, 'n': '0000000000000000', 'd': 0})
            pending['candidate'] = candidate
            def locally_mined():
                info = api(miner, '/info')
                return info if info['fullHeight'] == height else None
            local = wait_for(locally_mined, 'workload miner applies its block', timeout=60)
            mined = api(miner, '/blocks/' + local['bestFullHeaderId'])
            pending['block'] = mined
            save()
            after = wait_for(lambda: tips(height), 'mined workload reaches both nodes', timeout=60)
            pending['after'] = after
            ids = [tx['id'] for tx in mined['blockTransactions']['transactions']]
            if transaction['id'] not in ids:
                raise RuntimeError('DIVERGENCE: mined candidate omitted workload transaction')
            save()
        for stage, expected, total in (('sum-over-cap', 'RejectCost', CAP + 1),
                                       ('sum-at-cap', 'Accept', CAP), ('single-at-cap', 'Accept', CAP)):
            options = ['--campaign-stage', stage, '--funding', funding]
            if expected == 'RejectCost':
                options.append('--allow-cost-rejection')
            path = build(direction + '-' + stage, *options)
            block = json.loads(path.read_text())
            oracle = json.loads(Path(str(path) + '.oracle.json').read_text())
            if oracle['independent_tx_cost_sum'] != total:
                raise RuntimeError('JVM boundary does not match selected cap: ' + str(oracle))
            artifacts = retain_build(path)
            run['executed'] += 1
            record = inject(block, stage, expected, oracle)
            record['artifacts'] = artifacts
            if expected == 'RejectCost':
                for node, log in record['validation_logs'].items():
                    markers = ('CostLimitException',) if node == 'scala' else (
                        'BlockCostExceeded', f'block cost exceeded: total={CAP + 1}, limit={CAP}')
                    if not any(marker in log for marker in markers):
                        raise RuntimeError(node + ' lacks semantic cost rejection evidence')
                record['verdicts'] = {n: 'RejectCost' for n in URLS}
            run['manifest']['evidence'][str(path.relative_to(ROOT))] = sha(path)
            save()
        run['final'] = observations()
        run['status'] = 'PASS'
    except BaseException as error:
        run['status'] = 'DIVERGENT' if 'DIVERGENCE' in str(error) else 'BLOCKED'
        run['failed'] = 1
        run['error'] = str(error)
        run['failure_logs'] = {}
        for node in URLS:
            path = WORK / (node + '.log')
            if path.exists():
                run['failure_logs'][node] = archive(path)
        if any('EmissionInvariant' in (WORK / (n + '.log')).read_text().split('node starting')[-1]
               for n in ('rust',) if (WORK / (n + '.log')).exists()):
            run['status'] = 'DIVERGENT'
        try:
            run['final'] = {n: api(n, '/info') for n in URLS}
        except OSError:
            pass
        raise
    finally:
        try:
            subprocess.run([str(HERE / 'stop.sh')], check=True)
        finally:
            run['stopped'] = not any((WORK / (n + '.pid')).exists() for n in URLS)
            attempted = {item['selection']['case'] for item in run['workload']}
            attempted.update(item['case'] for item in run['injections'])
            run['skipped_items'] = [name for name in [item['case'] for item in selected] +
                ['sum-over-cap', 'sum-at-cap', 'single-at-cap'] if name not in attempted]
            run['skipped'] = len(run['skipped_items'])
            if 'context' in run['manifest']:
                run['manifest']['context']['height_range'][1] = run.get('final', {}).get('scala', {}).get('fullHeight')
            save()


if __name__ == '__main__':
    main()

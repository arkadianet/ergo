"""Capture JVM boundary verdicts without inferring them from measured costs."""
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys

from cost_fixture_io import fixture_paths, read_fixture_text, write_fixture_text

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'test-vectors/ergo-sigma/cost-ledger/sweeps'
VERIFY = 'scripts/jvm_evaluated_value_oracle/EvaluatedValueOracle.scala'
TX = 'scripts/jvm_cost_sweep_oracle/CostSweepOracle.scala'
SOURCE = 'test-vectors/scala/multi_input_conjunction_cost.json'



def _ergo_resources() -> str:
    """Ergo `src/main/resources` (holds `mainnet.conf`, read by both oracles).

    Not tracked here, so it must be supplied: `ERGO_RESOURCES`, or a checkout at
    the documented default location.
    """
    configured = os.environ.get('ERGO_RESOURCES')
    candidate = Path(configured) if configured else (
        Path.home() / 'coding/reference/ergo-core/ergo/src/main/resources'
    )
    if not (candidate / 'mainnet.conf').is_file():
        raise SystemExit(
            f'mainnet.conf not found under {candidate}; set ERGO_RESOURCES to the '
            "ergo checkout's src/main/resources (see scripts/gen-cost-sweep.sh)"
        )
    return str(candidate)


ERGO_RESOURCES = _ergo_resources()

def sha(data):
    return hashlib.sha256(data).hexdigest()


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True, stderr=subprocess.STDOUT).strip()


def scala(script, args, requests=None):
    argv = ['scala-cli', '--skip-cli-updates', 'run', script, '--server=false',
            '--suppress-outdated-dependency-warning', '--', *args]
    return subprocess.run(argv, cwd=ROOT, input=requests, stdout=subprocess.PIPE, check=True).stdout



# The replay helper lives here so the imported-only capture has one tracked source.
IMPORTED_ORACLE = r'''//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.2
//> using dep org.ergoplatform::ergo-core:6.0.2
//> using dep org.ergoplatform::ergo-wallet:6.0.2
import java.io.File
import java.nio.file.{Files, Paths}
import com.typesafe.config.ConfigFactory
import net.ceedubs.ficus.Ficus._
import net.ceedubs.ficus.readers.ArbitraryTypeReader._
import io.circe.Json
import org.ergoplatform._
import org.ergoplatform.modifiers.mempool.ErgoTransactionSerializer
import org.ergoplatform.nodeView.state.{ErgoStateContext, VotingData}
import org.ergoplatform.settings._
import org.ergoplatform.wallet.interpreter.ErgoInterpreter
import scorex.util.encode.Base16
import sigma.Colls
import sigma.data.CGroupElement
import sigma.serialization.{GroupElementSerializer, SigmaSerializer}
import sigmastate.eval.CPreHeader
import scala.util.{Success, Failure}
object ImportedSweepOracle extends PowSchemeReaders with ModifierIdReader with SettingsReaders {
  def main(args: Array[String]): Unit = {
    val config = ConfigFactory.defaultOverrides()
      .withFallback(ConfigFactory.parseFile(new File(args(0), "mainnet.conf")))
      .withFallback(ConfigFactory.parseFile(new File(args(0), "application.conf"))).resolve()
    implicit val chain: ChainSettings = config.as[ChainSettings]("ergo.chain")
    val source = io.circe.parser.parse(new String(Files.readAllBytes(Paths.get(args(1))), "UTF-8")).right.get
    val ctx = source.hcursor.downField("context")
    val voted = ctx.get[Map[String, Int]]("voted_params").right.get.map { case (k, v) => k.toByte -> v }
    val miner = GroupElementSerializer.parse(SigmaSerializer.startReader(Base16.decode(ctx.get[String]("miner_pk_hex").right.get).get))
    val cases = source.hcursor.get[Vector[Json]]("cases").right.get.map { entry =>
      val c = entry.hcursor
      val tx = ErgoTransactionSerializer.parseBytes(Base16.decode(c.get[String]("tx_bytes").right.get).get)
      val boxes = c.get[Vector[Json]]("input_boxes").right.get.map { b =>
        ErgoBox.sigmaSerializer.parse(SigmaSerializer.startReader(Base16.decode(b.hcursor.get[String]("bytes").right.get).get))
      }
      val points = c.get[Vector[Json]]("sweep").right.get.map { point =>
        val limit = point.hcursor.get[Int]("limit").right.get
        val params = Parameters(ctx.get[Int]("height").right.get, voted.updated(4.toByte, limit), ErgoValidationSettingsUpdate.empty)
        val context = new ErgoStateContext(Seq.empty, None, chain.genesisStateDigest,
          params, ErgoValidationSettings.initial, VotingData.empty) {
          override def sigmaPreHeader: sigma.PreHeader = CPreHeader(ctx.get[Int]("block_version").right.get.toByte,
            Colls.fromArray(Array.fill(32)(0.toByte)), ctx.get[Long]("timestamp").right.get,
            ctx.get[Long]("n_bits").right.get, ctx.get[Int]("height").right.get,
            CGroupElement(miner), Colls.fromArray(Array.fill(3)(0.toByte)))
        }
        implicit val verifier: ErgoInterpreter = new ErgoInterpreter(params)
        val result = tx.validateStateful(boxes, IndexedSeq.empty, context, accumulatedCost = 0L).result.toTry
        val (verdict, detail) = result match {
          case Success(_) => ("Accept", "")
          case Failure(error) =>
            val detail = error.toString
            require(detail.contains("CostLimitException") || detail.contains("initial cost") || detail.contains("cost exceeds limit") || detail.contains("assets cost"), detail)
            ("RejectCost", detail)
        }
        require(verdict == point.hcursor.get[String]("verdict").right.get, "imported verdict changed")
        Json.obj("limit" -> Json.fromInt(limit), "verdict" -> Json.fromString(verdict),
          "detail" -> Json.fromString(detail), "total" -> result.map(Json.fromLong).getOrElse(Json.fromString("unavailable")))
      }
      Json.obj("name" -> c.get[Json]("name").right.get, "points" -> Json.arr(points: _*))
    }
    Files.write(Paths.get(args(2)), Json.arr(cases: _*).spaces2.getBytes("UTF-8"))
  }
}
'''


def imported_points():
    with tempfile.TemporaryDirectory(dir=ROOT, prefix='.sweep-imported-') as tmp:
        script = Path(tmp) / 'ImportedSweepOracle.scala'
        script.write_text(IMPORTED_ORACLE)
        output = Path(tmp) / 'points.json'
        scala(str(script), [ERGO_RESOURCES,
                            SOURCE, str(output)])
        return {case['name']: case['points'] for case in json.loads(output.read_text())}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    original = json.loads((ROOT / SOURCE).read_text())
    manifest = copy.deepcopy(original['manifest'])
    manifest['rust'] = {'git_sha': command('git', 'rev-parse', 'HEAD'),
                        'toolchain': command('rustc', '--version'), 'features': ['test-helpers']}
    manifest['tool'] = {'script': 'scripts/gen-cost-sweep.sh', 'git_sha': command('git', 'rev-parse', 'HEAD'),
        'scala_cli_version': command('scala-cli', 'version', '--cli-version'),
        'jvm_version': command('java', '-version'),
        'script_sha256': {p: sha((ROOT / p).read_bytes()) for p in
                          [VERIFY, TX, 'scripts/gen_cost_sweep.py', 'scripts/gen-cost-sweep.sh']}}
    manifest['run'] = {'command': 'scripts/gen-cost-sweep.sh', 'seeds': 'TX-A/TX-B replay captured bytes; synthetic transactions use fresh keys',
                       'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    classes = {}

    def save(name, classes_for_file, source, ledger, accumulated, points, **fields):
        m = copy.deepcopy(manifest)
        m['context'] = {'network': 'synthetic offline mainnet settings',
                        **fields.pop('manifest_context', fields.get('context', original['context'])),
                        'accumulated_block_cost': accumulated, 'limit_override': 'points[].limit'}
        m['run'].update(selected=len(points), executed=len(points), skipped=0, failed=0)
        m['evidence'] = {'input_sha256': sha(read_fixture_text(ROOT / source).encode()),
                         'points_sha256': sha(json.dumps(points, sort_keys=True).encode()),
                         'replay_inputs_sha256': sha(json.dumps(fields, sort_keys=True).encode())}
        if source == SOURCE:
            m['evidence']['per_limit_oracle_sha256'] = sha(IMPORTED_ORACLE.encode())
            m['run']['command'] = 'scripts/gen-cost-sweep.sh --imported-only' if '--imported-only' in sys.argv[1:] else 'scripts/gen-cost-sweep.sh'
        result = dict(manifest=m, ledger=ledger, base_fixture=source,
                      accumulated_block_cost=accumulated, points=points, **fields)
        path = name + '.json.gz'
        m['evidence']['output_sha256'] = path + '.sha256 (uncompressed JSON)'
        rendered = json.dumps(result, indent=2) + '\n'
        write_fixture_text(OUT / path, rendered)
        (OUT / (path + '.sha256')).write_text(sha(rendered.encode()) + '  ' + path + '\n')
        for cls in classes_for_file:
            classes.setdefault(cls, []).append(path)

    replayed = imported_points()
    for case in original['cases']:
        points = replayed[case['name']]
        assert [(p['limit'], p['verdict']) for p in points] == [
            (p['limit'], p['verdict']) for p in case['sweep']]
        save(case['name'], [case['name']], SOURCE, ['LIMIT-per-input', 'TX-accumulator-shared'], 0,
             points, surface='transaction', case=case, context=original['context'], measured_total=case['block_cost'])
    if '--imported-only' in sys.argv[1:]:
        print('captured 6 imported sweep points in the original context')
        return
    with tempfile.TemporaryDirectory(dir=ROOT, prefix='.sweep-') as tmp:
        raw = Path(tmp) / 'tx.json'
        scala(TX, [ERGO_RESOURCES, str(raw), SOURCE])
        tx = json.loads(raw.read_text())
    base = 'test-vectors/ergo-sigma/cost-ledger/sweeps/base/transactions.json.gz'
    (ROOT / base).parent.mkdir(exist_ok=True)
    base_manifest = copy.deepcopy(manifest)
    base_manifest['scala']['artifacts'] = tx['artifacts']
    base_manifest['context'] = {'network': 'synthetic offline mainnet settings', **tx['context']}
    point_count = sum(len(case['sweep']) for case in tx['cases'])
    base_manifest['run'].update(selected=point_count, executed=point_count, skipped=0, failed=0)
    base_manifest['evidence'] = {'cases_sha256': sha(json.dumps(tx['cases'], sort_keys=True).encode())}
    base_manifest['evidence']['output_sha256'] = 'transactions.json.gz.sha256 (uncompressed JSON)'
    rendered_base = json.dumps(dict(manifest=base_manifest, **tx), indent=2) + '\n'
    write_fixture_text(ROOT / base, rendered_base)
    (ROOT / (base + '.sha256')).write_text(sha(rendered_base.encode()) + '  transactions.json.gz\n')
    for case in tx['cases']:
        cls = [case['name']] if case['name'] in ['TX-A', 'TX-B'] else []
        if case['name'] == 'TX-B':
            cls += ['later-input-exhaustion', 'init-only-exhaustion']
        rows = ['LIMIT-tx-start', 'LIMIT-per-input', 'TX-accumulator-shared']
        if case['name'] == 'rent-success':
            cls = ['storage-rent-success']
            rows = ['TX-storage-rent']
        if case['name'] == 'eval-remainders':
            cls = ['rounding-remainders']
            rows = ['ROUND-snap-per-input', 'LIMIT-per-input']
        if case['name'] == 'token-exhaustion':
            cls = ['token-exhaustion']
            rows = ['ORDER-init-token', 'LIMIT-tx-start']
        save(case['name'] + '-accumulated', cls, base, rows, case['accumulated_block_cost'],
             case['sweep'], surface='transaction', case=case, context=tx['context'], measured_total=case['block_cost'])
    selected = []
    for family in ['interpreter', 'op-fixed', 'op-per-item', 'eval', 'method', 'version']:
        directory = ROOT / 'test-vectors/ergo-sigma/cost-ledger/fixtures' / family
        for path in fixture_paths(directory):
            fixture = json.loads(read_fixture_text(path))
            case = next((c for c in fixture.get('cases', [fixture])
                         if c['expected']['verdict'] == 'Accept'
                         and c['expected']['total_block_cost'] != 'unavailable'
                         and not c['request'].get('rent')
                         and c['request']['tree_version_expected'] <= 3), None)
            if case:
                selected.append((family, str(path.relative_to(ROOT)), case['request'], ['L2-' + family], ['INTERP-costlimit-op']))
                break
        else:
            raise RuntimeError('no representative for ' + family)
    for filename in ['upcast-v2.json.gz', 'upcast-v2-wide.json.gz']:
        source = 'test-vectors/ergo-sigma/cost-ledger/fixtures/version/' + filename
        for index, case in enumerate(json.loads(read_fixture_text(ROOT / source))['cases']):
            selected.append((filename.split('.')[0] + '-' + str(index), source, case['request'],
                             ['pre-v3-upcast'], ['ORDER-pre-v3-upcast']))
    rent_source = 'test-vectors/ergo-sigma/verify/cases.json'
    for case in json.loads((ROOT / rent_source).read_text()):
        if case['name'] == 'rent_fallback':
            case['request']['ctx_ext_hex'] = '017f0302'  # Invalid output index triggers wallet recoverWith.
            selected.append((case['name'], rent_source, case['request'],
                             ['storage-rent-fallback'], ['TX-storage-rent']))
    p = ROOT / 'test-vectors/ergo-sigma/cost-ledger/fixtures/interpreter/p2pk.json.gz'
    r = json.loads(read_fixture_text(p))['request']
    r['proof_hex'] = ''
    selected.append(('failed-proof', str(p.relative_to(ROOT)), r,
                     ['failed-proof-at-C', 'competing-failures'], ['ORDER-crypto-before-verify']))
    def verify_many(requests):
        raw = scala(VERIFY, ['verify'], ''.join(json.dumps(r) + '\n' for r in requests).encode())
        responses = []
        for line in raw.splitlines():
            if line.startswith(b'{'):
                responses.append(json.loads(line))
            else:
                print(line.decode(), file=sys.stderr)
        assert len(responses) == len(requests), 'JVM response count mismatch'
        return responses

    baselines = [dict(item[2], init_cost_block=item[2]['init_cost_block'] + 1000,
                      cost_limit_block=1000000) for item in selected]
    measured = verify_many(baselines)
    assert len(measured) == len(selected)
    all_requests = []
    for request, result in zip(baselines, measured):
        cost = result['total_block_cost']
        assert isinstance(cost, int), result
        all_requests.extend(dict(request, cost_limit_block=limit) for limit in [cost - 1, cost, cost + 1])
    responses = verify_many(all_requests)
    assert len(responses) == len(all_requests)
    for index, (name, source, _, cls, rows) in enumerate(selected):
        request = baselines[index]
        points = [dict(limit=r['cost_limit_block'], verdict=e['verdict'], total=e['total_block_cost'])
                  for r, e in zip(all_requests[index * 3:index * 3 + 3], responses[index * 3:index * 3 + 3])]
        pre = bytes.fromhex(request['pre_header_hex'])
        save(name, cls, source, rows, 1000, points, surface='input', request=request, measured_total=measured[index]['total_block_cost'],
             manifest_context={'network': 'synthetic offline', 'height': int.from_bytes(pre[49:53], 'big'),
                 'activated_script_version': request['activated_version'], 'block_version': pre[0],
                 'voted_params': {str(i): None for i in range(4, 9)}})
    (OUT / 'CLASSES.toml').write_text('# Required task-4.1 sweep classes; every entry must execute.\n' +
        '\n'.join('[[classes]]\nname = ' + json.dumps(c) + '\nfiles = ' + json.dumps(files) + '\n'
                  for c, files in sorted(classes.items())))
    print(f'generated {len(list(OUT.glob("*.json.gz")))} sweeps, {len(classes)} classes')


if __name__ == '__main__':
    main()

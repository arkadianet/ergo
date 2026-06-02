// Extract Scala 2.12 HashTrieMap iteration order for u8 keysets.
//
// Compile / run:
//   javac -cp scala-library-2.12.18.jar ExtractHamtVectors.java
//   java  -cp scala-library-2.12.18.jar:. ExtractHamtVectors
//
// Produces the n=5/8/32/128 reference vectors §4.3 needs for true
// Scala-oracle parity (replacing the algorithm-self-derived expects
// in ergo-ser/src/scala_hamt.rs tests).

import scala.collection.immutable.HashMap;
import scala.collection.immutable.HashMap$;
import scala.Tuple2;

public class ExtractHamtVectors {

    public static void main(String[] args) {
        // Keysets matching the ones used in ergo-ser tests.
        int[][] sets = {
            {3, 17, 42, 99, 200},                       // n=5, named in test
            {11, 23, 47, 89, 137, 199, 251},            // n=7, idempotency test
            {3, 17, 42, 65, 99},                        // n=5, low-bit
            {131, 145, 170, 193, 227},                  // n=5, high-bit
            {3, 17, 42, 99, 137, 200, 230, 255},        // n=8, diverges test
            {5, 50, 100, 150, 200, 250},                // n=6
            {10, 20, 30, 40, 50, 60, 70, 80},           // n=8
            {1, 2, 3, 4, 5, 200},                       // n=6, mostly-ascending
            {0, 1, 2, 3, 4},                            // n=5, sequential
        };

        for (int[] keys : sets) {
            System.out.print("[");
            for (int i = 0; i < keys.length; i++) {
                if (i > 0) System.out.print(", ");
                System.out.print(keys[i]);
            }
            System.out.print("] -> [");
            int[] order = hamtOrder(keys);
            for (int i = 0; i < order.length; i++) {
                if (i > 0) System.out.print(", ");
                System.out.print(order[i]);
            }
            System.out.println("]");
        }
    }

    @SuppressWarnings("unchecked")
    static int[] hamtOrder(int[] keys) {
        // Build immutable HashMap[Byte, Integer] using Scala's HashMap$.
        // At >=5 entries Scala's factory switches from Map4 to HashTrieMap;
        // since we always pass >=5 here that's automatic.
        HashMap<Object, Object> m = HashMap$.MODULE$.empty();
        for (int k : keys) {
            byte b = (byte) k;
            m = m.$plus(new Tuple2<Object, Object>(b, k));
        }
        // Iterate in HAMT order.
        scala.collection.Iterator<Tuple2<Object, Object>> it = m.iterator();
        int[] out = new int[keys.length];
        int idx = 0;
        while (it.hasNext()) {
            Tuple2<Object, Object> pair = it.next();
            int key = ((Byte) pair._1()).intValue() & 0xFF;
            out[idx++] = key;
        }
        if (idx != keys.length) {
            throw new RuntimeException(
                "iterator yielded " + idx + " entries, expected " + keys.length
                    + " (duplicate key in input?)"
            );
        }
        return out;
    }
}

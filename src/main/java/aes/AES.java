package aes;

import io.vavr.control.Either;
import org.apache.commons.io.FilenameUtils;
import picocli.CommandLine;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.*;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static aes.OperationMode.CBC;
import static aes.OperationMode.ECB;


/**
 * @author Simona Bennárová
 */

@Command(name = "aes", mixinStandardHelpOptions = true,
        description = "Encrypt or decrypt file using Advanced Encryption Standard", version = "1.0")
public class AES implements Callable<Integer> {

    private int[] expandedKeys;
    private Map<Integer, Integer> rconCache;

    public static final int[] sbox = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

    private static final int[] invsbox = {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

    private int Nr; // number of rows
    private int Nk;
    private final int Nb = 4; //number of bytes per row

    @Option(names = {"-m", "--mode"}, description = "ECB or CBC mode")
    private OperationMode mode = ECB;

    @Option(names = { "-k", "--key" }, required = true, paramLabel = "KEY", description = "Secret key filename. Length needs to be 128, 192 or 256 bits.")
    private File key;

    @Option(names = { "-t", "--text" }, paramLabel = "TEXT", required = true, description = "Plaintext or ciphertext filename")
    private File text;

    @Option(names = {"--IV" }, paramLabel = "TEXT", description = "Initialization vector. Length needs to be 128 bits.")
    private String IV;

    @ArgGroup(exclusive = true, multiplicity = "1")
    private Exclusive encryptOrDecrypt;

    static class Exclusive {
        @Option(names = "-e", description = "Encrypt text", required = true) boolean e;
        @Option(names = "-d", description = "Decrypt text", required = true) boolean d;
    }

    private AES() {
        this.rconCache = rconInit();
    }

    /**
     * Verify key length and return Nr value according to key length
     * @param key
     * @return Optional.empty if key length is invalid or Nr
     */
    private Optional<Integer> keyValidation(int[] key) {
        switch (key.length) {
            case 16: return Optional.of(10);
            case 24: return Optional.of(12);
            case 32: return Optional.of(14);
            default: return Optional.empty();
        }
    }

    /**
     * Initialize rconCache
     * @return initialize rconCache
     */
    private Map<Integer, Integer> rconInit() {
        return Stream.of(
                new AbstractMap.SimpleEntry<>(1,0x01),
                new AbstractMap.SimpleEntry<>(9, 0x1b))
                .collect(Collectors.toMap(HashMap.Entry::getKey, HashMap.Entry::getValue));
    }

    /**
     * reads from input and converts it to int array
     * @param input
     * @return converted int array
     */
    private static int[] textToIntArray(BufferedReader input) throws IOException {
        int[] array =  input.lines()
                .flatMapToInt(line-> (line + '\n').chars())
                .toArray();
        return Arrays.copyOfRange(array, 0, array.length -1);
    }


    public static void main(String[] args) {

        new CommandLine(new AES()).execute(args);

    }

    @Override
    public Integer call() throws Exception {
        AES aes = new AES();

        int[] textReader, keyReader;
        if (!text.exists() || !key.exists()) {
            System.out.println("Invalid path to file.");
            return 1;
        }

        textReader = textToIntArray(new BufferedReader(new FileReader(text)));
        keyReader = textToIntArray(new BufferedReader(new FileReader(key)));
        Either<String, int[]> encryptedText;

        if (encryptOrDecrypt.e) {
            encryptedText = encryptText(textReader, keyReader, mode, IV.chars().toArray());
            if (encryptedText.isLeft()) {
                System.out.println(encryptedText.getLeft());

            } else {
                String name = FilenameUtils.removeExtension(text.getName());
                System.out.println("Encryption succesful.\nEncrypted content of file " + text.getName() +" is in file " + name +".enc");

                FileWriter encrypted = new FileWriter(name + ".enc");
                encrypted.write(Arrays.stream(encryptedText.get()).collect(StringBuilder::new,
                        StringBuilder::appendCodePoint, StringBuilder::append)
                        .toString());
                encrypted.close();
            }
        }
        if (encryptOrDecrypt.d) {
            encryptedText = aes.decryptText(textReader, keyReader, mode, IV.chars().toArray());
            if (encryptedText.isLeft()) {
                System.out.println(encryptedText.getLeft());
            } else {
                String name = FilenameUtils.removeExtension(text.getName());
                System.out.println("Decryption succesful.\nDecrypted content of file " + text.getName() +" is in file " + name +".dec");
                FileWriter decrypted = new FileWriter(name + ".dec");
                decrypted.write(Arrays.stream(encryptedText.get()).collect(StringBuilder::new,
                        StringBuilder::appendCodePoint, StringBuilder::append)
                        .toString());
                decrypted.close();
            }
        }
        return 0;
    }

    private int[] fileToArray(File text) throws IOException {
        String all = new String(Files.readAllBytes(text.toPath()));
        return all.chars().toArray();
    }



    /**
     * Encrypts whole text
     * @param text plaintext
     * @param key used in encryption
     * @param mode either ECB or CBC
     * @param IV   16 byte inicialization vector used in CBC mode
     * @return ciphertext or error
     */
    private Either<String, int[]> encryptText(int[] text, int[] key, OperationMode mode , int[] IV) {
        Optional<int[]> maybeKeys = keyExpansion(key);

        if (!maybeKeys.isPresent()) {
            return Either.left("Invalid key length.");
        } else {
            expandedKeys = maybeKeys.get();
        }

        if (mode == CBC && IV == null)
            return Either.left("IV missing.");

        if (mode == CBC && IV.length != 16)
            return Either.left("IV length must be 16 bytes.");

        int[] encrypted;
        if (mode == ECB ) {
            encrypted = Arrays.stream(chunksOfSixteen(text))
                    .parallel()
                    .map(this::encryptBlock)
                    .flatMapToInt(Arrays::stream)
                    .toArray();

        } else { // OperationMode == CBC
            PreviousWrapper previous = new PreviousWrapper(IV);
            encrypted = Arrays.stream(chunksOfSixteen(text))
                    .map(block -> {
                        previous.value = encryptBlock(xor16(block, previous.value)); // Ci = encrypt(Ci-1 xor Pi)
                        return previous.value;
                    })
                    .flatMapToInt(Arrays::stream)
                    .toArray();

        }
        return Either.right(encrypted);
    }

    /**
     * decrypt cipher text
     * @param ciphertext
     * @param key
     * @param mode
     * @param IV
     * @return plaintext or error
     */
    private Either<String, int[]> decryptText(int[] ciphertext, int[] key, OperationMode mode, int[] IV) {
        Optional<int[]> maybeKeys = keyExpansion(key);
        if (!maybeKeys.isPresent()) {
            return Either.left("Invalid key length.");
        } else {
            expandedKeys = maybeKeys.get();
        }

        if ((mode == CBC && IV == null))
            return Either.left("IV missing.");

        if (mode == CBC && IV.length != 16)
            return Either.left("IV length must be 16 bytes.");

        if ((ciphertext.length % 16 != 0))
            return Either.left("Something went wrong, invalid length of cipher text.");

        int[] plaintext;
        if (mode == ECB) {
            plaintext = Arrays.stream(chunksOfSixteen(ciphertext))
                    .parallel()
                    .map(this::decryptBlock)
                    .flatMapToInt(Arrays::stream)
                    .toArray();
        } else { // OperationMode == CBC
            plaintext = decryptTextCBC(chunksOfSixteen(ciphertext), IV);
        }

        return Either.right(plaintext);
    }

    /**
     * CBC mode for decryption
     * @param ciphertext
     * @param IV
     * @return plaintext
     */
    private int[] decryptTextCBC(int[][] ciphertext, int[] IV) {
        Stream<int[]> c = Arrays.stream(ciphertext);
        Stream<int[]> cMinus1 = Stream.concat(Stream.of(IV), Arrays.stream(Arrays.copyOfRange(ciphertext,0, ciphertext.length-1)));

        Stream.Builder<int[]> builder = Stream.builder();

        Spliterator<int[]> cSpltr = c.spliterator();
        Spliterator<int[]> cMinus1Spltr = cMinus1.spliterator();

        cSpltr.forEachRemaining((int[] cT) -> {
            // Pi = decrypt(Ci) xor Ci-1
            cMinus1Spltr.tryAdvance((int[] cMinus1T) -> {
                builder.accept(xor16(decryptBlock(cT), cMinus1T));
            });
        });
        return builder.build().flatMapToInt(Arrays::stream).toArray();

    }

    private class PreviousWrapper {
        private int[] value;

        private PreviousWrapper(int[] v) {
            this.value = v;
        }
    }

    /**
     * encrypt one block of text
     * @param state 16 bytes block
     * @return encrypted block
     */
    private int[] encryptBlock(int[] state) {
        Function<int[], int[]> subBytes = this::subBytes;
        Function<int[], int[]> addRoundKey0 = arr -> addRoundKey(arr,0);

        BiFunction<int[], Integer, int[]> round = (stateR, roundNumber) -> subBytes
                .andThen(this::shiftRows)
                .andThen(this::mixColumns)
                .andThen(arr -> addRoundKey(arr, roundNumber))
                .apply(stateR);

        BiFunction<Integer, int[], int[]> nRounds = (numberOfrounds, stateR) -> IntStream.range(1, numberOfrounds)
                .mapToObj(i -> new int[]{i})
                .reduce(stateR, (int[] rState, int[] roundN) -> round.apply(rState, roundN[0]));

        return addRoundKey0
                .andThen(arr -> nRounds.apply(Nr, arr))
                .andThen(this::subBytes)
                .andThen(this::shiftRows)
                .andThen(arr -> addRoundKey(arr, Nr))
                .apply(state);
    }

    /**
     * decrypt one block of plaintext
     * @param state 16 bytes block
     * @return block of plaintext
     */
    private int[] decryptBlock(int[] state) {
        Function<int[], int[]> invShiftRows = this::invShiftRows;
        Function<int[], int[]> addRoundKey0 = arr -> addRoundKey(arr, Nr);

        BiFunction<int[], Integer, int[]> round = (stateR, roundNumber) -> invShiftRows
                .andThen(this::invSubBytes)
                .andThen(arr -> addRoundKey(arr, roundNumber))
                .andThen(this::invMixColumns)
                .apply(stateR);

        BiFunction<Integer, int[], int[]> nRounds = (numberOfrounds, stateR) -> IntStream
                .range(1, Nr)
                .mapToObj(i -> new int[]{Nr -i})
                .reduce(stateR, (int[] rState, int[] roundN) -> round.apply(rState, roundN[0]));

        return addRoundKey0
                .andThen(arr -> nRounds.apply(Nr, arr))
                .andThen(this::invShiftRows)
                .andThen(this::invSubBytes)
                .andThen(arr -> addRoundKey(arr, 0))
                .apply(state);
    }

    private int[] invSubBytes(int[] state) {
        return Arrays.stream(state)
                .parallel()
                .map(b -> invsbox[(b/16)*16 + b % 16])
                .toArray();
    }

    /**
     * substitute each byte of state with value from sbox
     * @param state array of 16 bytes
     * @return state with substitute values
     */
    private int[] subBytes(int[] state){
        return Arrays.stream(state)
                .parallel()
                .map(b -> sbox[(b/16)*16 + b % 16])
                .toArray();
    }

    /**
     * shift cyclically each row of state by 0, 1, 2, 3 to the right
     * @param state block
     * @return shifted array
     */
    private int[] invShiftRows(int[] state) {
        final int[] opyState = Arrays.copyOf(state,16);
        return IntStream.range(0,4)
                .parallel()
                .mapToObj(i -> {
                    int[] arr = Arrays.copyOfRange(opyState, 4*i, 4*i+4);
                    return IntStream.concat(Arrays.stream(arr), Arrays.stream(arr))
                            .skip(4-i)
                            .limit(4).toArray();
                })
                .flatMapToInt(Arrays::stream)
                .toArray();
    }

    /**
     * shift cyclically each row of state by 0, 1, 2, 3 to the left
     * @param state
     * @return shifted array
     */
    private int[] shiftRows(int[] state) {
        return IntStream.range(0,4)
                .mapToObj(i -> {
                    int[] arr = Arrays.copyOfRange(state, 4*i, 4*i+4);
                    return IntStream.concat(Arrays.stream(arr), Arrays.stream(arr))
                            .skip(i)
                            .limit(4).toArray();
                })
                .flatMapToInt(Arrays::stream)
                .toArray();
    }

    /**
     * expand key to 10,12 or 14 round keys
     * @param key - 128, 192 or 256 bits long key
     * @return array of round keys
     */
    private Optional<int[]> keyExpansion(int[] key) {

        Optional<Integer> nr = keyValidation(key);
        if (!nr.isPresent())
            return Optional.empty();
        Nr = nr.get();
        Nk = Nr - 6;

        int[][] words = new int[Nb*(Nr+1)][Nk];
        IntStream.range(0,Nk).forEach(j -> words[j] = Arrays.copyOfRange(key, j*4, j*4+4));
        IntStream.range(Nk, Nb * (Nr+1)).forEach(i -> {
                    final int[] temp;
                    if (i % Nk == 0) {
                        temp = IntStream.concat(Arrays.stream(words[i-1]), Arrays.stream(words[i-1]))
                                .skip(1)
                                .limit(4)
                                .map(ind -> sbox[(ind/16)*16 + ind % 16])
                                .toArray();
                        temp[0] ^= rcon(i/Nk);
                    } else if (Nk > 6 && i % Nk == 4) {
                        temp = Arrays.stream(words[i - 1])
                                .map(ind -> sbox[ind / 16* 16 + ind % 16])
                                .toArray();
                    } else {
                        temp = words[i - 1];
                    }

                    words[i] = xor16(words[i - 4], temp);
        });
        return Optional.of(Arrays.stream(words).flatMapToInt(Arrays::stream).toArray());
    }

    /**
     * computes round constant values
     * @param i index of round constant
     * @return round constant value on index i
     */
    private int rcon(int i) {
        Integer rcon = rconCache.get(i);
        if (rcon == null) {
            rcon = (2*rcon(i-1)) % 0xff;
            rconCache.put(i, rcon);
        }
        return rcon;
    }

    /**
     * xor state block with round key
     * @param state
     * @param i index of round key
     * @return xored round key with state
     */
    private int[] addRoundKey(int[] state, int i) {
        int[] roundKey = Arrays.copyOfRange(expandedKeys, i*16, (i+1)*16);
        return xor16(state, roundKey);
    }

    /**
     * Galois table used for mixColumns
     */
    private static final int[][] galois = {
            {2, 3, 1, 1},
            {1, 2, 3, 1},
            {1, 1, 2, 3},
            {3, 1, 1, 2}};

    /**
     * Inverse Galois table used for invMixColumns
     */
    private static final int[][] invgalois = {
            {14, 11, 13, 9},
            {9, 14, 11, 13},
            {13, 9, 14, 11},
            {11, 13, 9, 14}};

    private class IntWrapper {
        private int value;

        private IntWrapper(int v) {
            this.value = v;
        }
    }


    /**
     * Galois Field (256) Multiplication of two Bytes
     * @param a first byte to multiply
     * @param b second byte to multiple
     * @return multiplication of a nad b over Galois Field
     */
    private int gMul(int a, int b) { //
        IntWrapper ai = new IntWrapper(a);
        IntWrapper bi = new IntWrapper(b);

        return IntStream.range(0, 8)
                .reduce(0, (p, counter) -> gMulOneBit(ai, bi, p));

    }

    /**
     * Galois Field (256) Multiplication on one bit
     * @param ai helper variable
     * @param bi helper variable
     * @param p  intermediate result
     * @return byte p
     */
    private int gMulOneBit(IntWrapper ai, IntWrapper bi, int p)
    {
        if ((bi.value & 1) != 0)
            p ^= ai.value;

        boolean hi_bit_set = (ai.value & 0x80) != 0;
        ai.value = ((ai.value << 1) & 0xFF);

        if (hi_bit_set)
            ai.value = ai.value^0x1B; /* x^8 + x^4 + x^3 + x + 1 */

        bi.value = bi.value >> 1;
        return p & 0xFF;
    }

    /**
     * multiply each column with matrix over GF(2)
     * @param state
     * @param isInv if true invgalois matrix is used otherwise galois matrix is used
     * @return array
     */
    private int[] mixColumnsUniversal(int[] state, boolean isInv) {
        int[] statetmp = new int[16];
        IntStream.range(0,4)
                .forEach(c -> IntStream.range(0,4)
                        .forEach(i -> statetmp[i*4+c] = galoisXor(state, c, i, isInv ? invgalois : galois)));
        return statetmp;

    }

    private int[] invMixColumns(int[] state) {
        return mixColumnsUniversal(state, true);
    }

    private int[] mixColumns(int[] state) {
        return mixColumnsUniversal(state, false);

    }


    private int galoisXor(int[] state, int c, int i, int[][] galois) {
        AtomicInteger index = new AtomicInteger(0);
        return Arrays.stream(galois[i])
                .map(el -> gMul(el, state[index.getAndIncrement()*4+c]))
                .reduce(0, (x, y) -> x^y);
    }

    /**
     * xor 16 bytes array with 16 byte array
     * @param first
     * @param second
     * @return array
     */
    private int[] xor16(int[] first, int[] second) {
        return IntStream.range(0, first.length)
                .parallel()
                .map(index -> first[index] ^ second[index])
                .toArray();
    }

    /**
     * cut array into arrays of 16 elements
     * @param array
     * @return array of arrays
     */
    private int[][] chunksOfSixteen(int[] array) {
        int size = array.length % 16 == 0 ? array.length : ((array.length / 16) +1)*16;
        int[] paddedArray = new int[size];
        Arrays.fill(paddedArray, ' ');
        System.arraycopy(array, 0, paddedArray, 0, array.length);
        int rows = size / 16;
        return IntStream.range(0, rows)
                .parallel()
                .mapToObj(i -> Arrays.copyOfRange(paddedArray, 16 * i, (i+1)*16))
                .toArray(int[][]::new);

    }



}

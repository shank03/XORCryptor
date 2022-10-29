public class Main {

    public static void main(String[] args) {
        String input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis ornare.",
                key = "secret_key";
        String encrypted = XORCryptor.encrypt(input, key);
        System.out.println(encrypted);
        System.out.println(XORCryptor.decrypt(encrypted, key));
    }
}
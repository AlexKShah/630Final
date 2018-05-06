/**
 * This class takes the user input key and calls aescipher class for processing
 * the keys.If the input is less than 32 bits, then it pads and processes
 */

public class Driver {

  public static void main(String[] args) {


    long startTime0 = System.nanoTime();
    String plainText = "";
    String inputkey = args[0].toUpperCase();
    plainText = args[1].toUpperCase();
    String verbose = args[2];
    int row_size = 0;
    int column_size = 0;
    int rounds = 0;
    int inputLength = plainText.length();
    int padLength = 32 - plainText.length();
    String padString = Integer.toString(padLength);
    if (padLength < 10)
      padString = "0".concat(padString);
    int[] size_basket = new int[4];

    /**
     * Assigning values based on input key size
     */
    if (inputkey.length() == 32) {
      row_size = 4;
      column_size = 44;
      rounds = 11;
    } else if (inputkey.length() == 48) {
      row_size = 6;
      column_size = 52;
      rounds = 13;
    } else if (inputkey.length() == 64) {
      row_size = 8;
      column_size = 60;
      rounds = 15;
    }
    size_basket[0] = row_size;
    //System.out.println("row size = "+row_size);
    size_basket[1] = column_size;
    //System.out.println("col size = "+column_size);
    size_basket[2] = rounds;
    //System.out.println("rounds = "+rounds);

    long endTime0 = System.nanoTime();
    long duration0 = (endTime0 - startTime0);  //divide by 1000000 to get milliseconds.
    System.out.println(("========Time0 Driver Variable Assignment: " + duration0));
    /**
     * Based on input message size padding is decided
     */
    try {
      if (plainText.length() == 32 && plainText.substring(30, 32) == "00") {
        long startTime1 = System.nanoTime();
        String cipher = Aescipher.processInput(plainText, inputkey, size_basket, verbose);
        long endTime1 = System.nanoTime();
        long duration1 = (endTime1 - startTime1);  //divide by 1000000 to get milliseconds.
        System.out.println(("========Time1 Driver call to Aescipher.processinput1: " + duration1));

        if (verbose.equals("1")) {
          System.out.println("Encrypted message is");
          System.out.println(cipher);
        }

      } else if (plainText.length() <= 30) {

        for (int i = 0; i < padLength / 2; i++) {
          plainText = plainText.concat(padString);
        }

      }

      long startTime2 = System.nanoTime();
      String cipher = Aescipher.processInput(plainText, inputkey, size_basket, verbose);
      long endTime2 = System.nanoTime();
      long duration2 = (endTime2 - startTime2);  //divide by 1000000 to get milliseconds.
      System.out.println(("========Time2 Driver call to Aescipher.processInput2: " + duration2));

      if (verbose.equals("1")) {
        System.out.println("Encrypted message is");
        System.out.println(cipher);
      }

      long startTime3 = System.nanoTime();
      String decipher = Aesdecipher.processInput(cipher, inputkey, size_basket).toUpperCase();
      long endTime3 = System.nanoTime();
      long duration3 = (endTime3 - startTime3);  //divide by 1000000 to get milliseconds.
      System.out.println(("========Time3 Driver call to Aesdecipher.processinput3: " + duration3));

      long startTime4 = System.nanoTime();
      if (padLength > 0) {
        if (verbose.equals("1")) {
          System.out.println("Number of bits to be padded are ");
          System.out.println(padLength);
        }
        decipher = decipher.substring(0, inputLength);
      }

      if (verbose.equals("1")) {
        System.out.println("Decrypted message is");
        System.out.println(decipher);
      }

      if (!args[1].equals(decipher)) {
        System.out.println("penalty");
        try {
          Thread.sleep(10);
        } catch (InterruptedException ex) {
          Thread.currentThread().interrupt();
        }
      }

    long endTime4 = System.nanoTime();
    long duration4 = (endTime4 - startTime4);  //divide by 1000000 to get milliseconds.
    System.out.println(("========Time4 Driver final stuff: " + duration4));
    } catch (Exception se) {
      se.printStackTrace();
    }


  }
}

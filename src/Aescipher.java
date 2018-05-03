/**
 * File: Aescipher.java
 * <p>
 * It accepts user input, key and decrypts
 * the cipher
 */

/*
TODO
processinput(): String
->

generateWMatrix(
  col_valueforInput = 8 (rows),
  column size = 60 (cols),
  rounds = 15
): String
->

generateCipher(
  inHex, user provided key
  masterText_encrypt, user plaintext
  column_size = 60 (cols)
  col_valueforInput = 8 (rows),
  rounds = 15
): String
 */

public class Aescipher {

  // masterKey array is declared to save the key user gives
  public static String[][] inHex;
  public static String[][] masterText_encrypt;
  // keyMatrixW array is declared to save the key's which will be generated
  public static String[][] W;
  static String[][] GaloisMatrix = {{"02", "03", "01", "01"}, {"01", "02", "03", "01"},
      {"01", "01", "02", "03"}, {"03", "01", "01", "02"}};

  /**
   * This method accepts user given key and saves it into a 4*4 matrix. Once
   * the input is processed generateWMatrix() method is called.
   *
   * @param inputKey : Input key
   */
  public static String processInput(String plainText, String inputKey, int[] size_basket, String verbose) {
    String cipherFinal = "";
    int i = 0;
    int j = 0;
    int numRows;
    int numCols;
    int numRounds;
    numRows = size_basket[0];
    numCols = size_basket[1];
    numRounds = size_basket[2];
    W = new String[4][numCols];
    inHex = new String[4][numRows];
    masterText_encrypt = new String[4][4];
    for (int column = 0; column < numRows; column++) {
      for (int row = 0; row < 4; row = row + 1) {
        inHex[row][column] = inputKey.substring(i, i + 2);
        i = i + 2;
      }
    }

    for (int column = 0; column < 4; column++) {
      for (int row = 0; row < 4; row = row + 1) {
        masterText_encrypt[row][column] = plainText.substring(j, j + 2);
        j = j + 2;
      }
    }
    if (verbose.equals("1")) {
      System.out.println("Text to be encrypted after padding is");
      System.out.println(plainText);
    }
    cipherFinal = generateWMatrix(numRows, numCols, numRounds);
    //cipherFinal = newGenerateWMatrix(numRows, numCols, numRounds);

    return cipherFinal;
  }

  public static String generateCipher(String[][] masterKey, String[][] masterText, int column_size, int row_size,
                                      int rounds) {


    String[][] keyHex = new String[4][4];
    StringBuilder outValue = new StringBuilder();
    int WCol = 0;
    int roundCounter = 0;
    while (WCol < column_size) {
      for (int cols = 0; cols < 4; cols++, WCol++) {
        for (int row = 0; row < 4; row++) {
          keyHex[row][cols] = W[row][WCol];
        }
      }
      System.out.println("key hex = " + MatrixToString(keyHex));

      if (roundCounter != (rounds - 1)) {
        masterText = aesStateXor(masterText, keyHex);
        // Exclusive or output is passed to nibble substitution is
        // called
        masterText = aesNibbleSub(masterText);
        // Nibble substituted output is called to shiftrows method
        masterText = aesShiftRow(masterText);
        // Shifted output is sent to mixing columns function
        if (roundCounter != (rounds - 1)) {
          masterText = aesMixColumn(masterText);
        }

      } else
        // In the tenth round we do only plain xor
        masterText = aesStateXor(masterText, keyHex);
    }
    // System.out.println("The Cipher Text is");
    for (int cols = 0; cols < 4; cols++) {
      for (int row = 0; row < 4; row++) {
        outValue = outValue.append(masterText[row][cols]);
        // System.out.print(masterText[row][cols]+ "\t");
      }

    }
    //System.out.println();
    // Aesdecipher.processInput(outValue, inputkey, size_basket);
    return outValue.toString();

  }
  //from decipher
  public static String generateWMatrix(int rowSize, int columnSize, int rounds) {
    String cipherW = "";
    for (int row = 0; row < 4; row = row + 1) {
      for (int column = 0; column < rowSize; column++) {
        W[row][column] = inHex[row][column];
      }
    }
    /**
     * generating remaining elements in array to fill 40 columns
     */
    for (int column = rowSize; column < columnSize; column++) {
      /**
       * if colum is multiple of given value, it goes to for loop for
       * X-or
       */
      if (column % rowSize != 0) {
        if (column % 4 == 0 && rowSize == 8) {
          for (int row = 0; row < 4; row++) {
            W[row][column] = aesSbox(W[row][column - 1]);
            W[row][column] = exclusiveOr(W[row][column], W[row][column - rowSize]);
          }
        } else
          for (int row = 0; row < 4; row++) {

            W[row][column] = exclusiveOr(W[row][column - rowSize],
                W[row][column - 1]);
          }
      } else {
        /**
         * creating a new matrix for storing elements
         */
        String[][] wNew = new String[1][4];
        // Shifting the columns
        wNew[0][0] = W[1][column - 1];
        wNew[0][1] = W[2][column - 1];
        wNew[0][2] = W[3][column - 1];
        wNew[0][3] = W[0][column - 1];
        // aesSbox method is called for getting S-box values for
        // corresponding elemetns
        for (int i = 0; i < 4; i++) {
          wNew[0][i] = aesSbox(wNew[0][i]);
        }
        int r = column / rowSize;
        String rconVal = aesRcon(r);
        wNew[0][0] = exclusiveOr(wNew[0][0], rconVal);
        for (int row = 0; row < 4; row++) {
          W[row][column] = exclusiveOr(W[row][column - rowSize], wNew[0][row]);
        }

      }
    }
    cipherW = generateCipher(inHex, masterText_encrypt, columnSize, rowSize, rounds);
    return cipherW;
  }
  /**
   * generateWMatrix() method starts processing the keys for the 4*44 keys
   * matrix
   */

//  //REVISED
//  public static String generateWMatrix(int numRows, int numCols, int numRounds) {
//    //copy in key hex
//    for (int i = 0; i < 4; i++) {
//      W[i][0] = inHex[i][0];
//      W[i][1] = inHex[i][1];
//      W[i][2] = inHex[i][2];
//      W[i][3] = inHex[i][3];
//    }
//
//    for (int column = 4; column < numCols; column++) {
//      /**
//       * if the column number is not a multiple of 4 the following steps
//       * are to be implemented
//       */
//
//      //column is divisible by 4
//      if (column % 4 != 0) {
//        //column not divisible by 4
//        // 3a: w(j) = w(j − 4) XOR w(j − 1)
//        for (int row = 0; row < 4; row++) {
//          W[row][column] = exclusiveOr(W[row][column - 4], W[row][column - 1]);
//        }
//
//      } else {
//        // 3b
//        // wnew = [ (Rcon(i) XOR Sbox(w1,j−1)), Sbox(w2,j−1), Sbox(w3,j−1), Sbox(w0,j−1) ]
//        // w(j) = w(j − 4) XOR wnew
//        // wnew = [ (Rcon(i) XOR Sbox(w1,j−1)), Sbox(w2,j−1), Sbox(w3,j−1), Sbox(w0,j−1) ]
//        String[] wnew = new String[4];
//        int r = column / numRows;
//        String rconValue = aesRcon(r);
//        wnew[0] = exclusiveOr(rconValue, aesSbox(W[1][column - 1]));
//        wnew[1] = aesSbox(W[2][column - 1]);
//        wnew[2] = aesSbox(W[3][column - 1]);
//        wnew[3] = aesSbox(W[0][column - 1]);
//
//        // w(j) = w(j − 4) XOR wnew
//        for (int row = 0; row < 4; row++) {
//          W[row][column] = exclusiveOr(W[row][column - 4], wnew[row]);
//        }
//      }
//    }
//    String cipherW = "";
//    cipherW = generateCipher(inHex, masterText_encrypt, numCols, numRows, numRounds);
//    return cipherW;
//  }

  public static String MatrixToString(String[][] matrix) {
    String ctxt = "";
    for (int row = 0; row < 4; row++) {
      ctxt += matrix[row][0];
      ctxt += matrix[row][1];
      ctxt += matrix[row][2];
      ctxt += matrix[row][3];
    }
    return ctxt.toUpperCase();
  }

  /**
   * This method takes two input strings which are hexadecimal values and
   * convert them into decimal and performe exclusive OR. Saves and returns
   * the result back.
   *
   * @param val1 : Inputs to be XORed
   * @param val2 : Inputs to be XORed
   * @return : Returns hexadecimal string after exclusive OR operation
   */
  private static String exclusiveOr(String val1, String val2) {
    int decimalValue1 = Integer.parseInt(val1, 16);
    int decimalValue2 = Integer.parseInt(val2, 16);
    int exclusiveOutput = decimalValue1 ^ decimalValue2;
    String hexResult = Integer.toHexString(exclusiveOutput);
    return hexResult.length() == 1 ? ("0" + hexResult) : hexResult;
  }

  /**
   * This method takes a hexadecimal value as the input, splits it and
   * converts into decimal. Based on the two integers generated we map the
   * S_BOX matrix and find the respective value and return it back.
   *
   * @param sBoxInput : String which is split and used as index on s_box
   * @return : Returns the value from s-box matrix
   */
  private static String aesSbox(String sBoxInput) {

    int firstDigitInt = Integer.parseInt(sBoxInput.split("")[0], 16);
    int secondDigitInt = Integer.parseInt(sBoxInput.split("")[1], 16);
    String sboxOutput = S_BOX[firstDigitInt][secondDigitInt];
    return sboxOutput;
  }

  /**
   * This method takes a the string and finds the respective element in the
   * R_CON matrix.
   *
   * @param rConInput : Index to lookup R_CON matrix
   * @return : Value from the R_CON matrix
   */
  private static String aesRcon(int rConInput) {

    String rConOutput = R_CON[0][rConInput];
    return rConOutput;
  }

  public static String[][] aesStateXor(String[][] sHex, String[][] keyHex) {
    String exclusiveOrArray[][] = new String[4][4];
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
        exclusiveOrArray[i][j] = exclusiveOr(sHex[i][j], keyHex[i][j]);
      }
    }

    return exclusiveOrArray;

  }

  /**
   * Accepts Exclusiveor output and finds the respective element in S_BOX
   * matrix
   *
   * @param exclusive
   * @return
   */
  public static String[][] aesNibbleSub(String[][] exclusive) {
    String sBoxValues[][] = new String[4][4];
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
        sBoxValues[i][j] = aesSbox(exclusive[i][j]);
      }
    }
    return sBoxValues;
  }

  /**
   * Once the S_BOX values are returned they are shifted
   *
   * @param sHex
   * @return
   */
  public static String[][] aesShiftRow(String[][] sHex) {
    String[][] outStateHex = new String[4][4];
    int counter = 4;
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
        if (i > 0)
          outStateHex[i][(j + counter) % 4] = sHex[i][j];

        else
          outStateHex[i][j] = sHex[i][j];
      }
      counter--;
    }
    return outStateHex;
  }

  protected static String[][] aesMixColumn(String[][] inStateHex) {
    String sum;
    String Product[][] = new String[4][4];

    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
        sum = "0";
        for (int k = 0; k < 4; k++) {

          switch (GaloisMatrix[i][k]) {
            // checks data from galios matrix and verifies data to
            // perform
            // multiplication
            case "01":
              sum = exclusiveOr(sum, inStateHex[k][j]);
              break;
            case "02":
              // If its 02 then multiply2 function is called
              sum = exclusiveOr(sum, multiply2(inStateHex[k][j]));
              break;
            case "03":
              // If its 02 then multiply3 function is called
              sum = exclusiveOr(sum, multiply3(inStateHex[k][j]));
              break;
          }
        }

        Product[i][j] = sum;
      }
    }
    return Product;
  }

  /**
   * In this function , mix columns operations having multiplication
   * with 3 are considered here and operation is performed.
   *
   * @param InputHex
   * @return
   */
  protected static String multiply3(String InputHex) {
    return exclusiveOr(multiply2(InputHex), InputHex);
  }

  /**
   * In Mix columns operation if the element is to be multiplied with 2, we
   * will use this function to perform the operation of checking most
   * significant bit shifting the bits
   *
   * @param InputHex
   * @return
   */
  protected static String multiply2(String InputHex) {
    // String Input = InputHex.length() < 8 ? ("0" + InputHex) : InputHex;
    InputHex = Integer.toBinaryString(Integer.parseInt(InputHex, 16));
    int lenthOfInput = 8 - (InputHex.length());
    String pads = new String();
    for (int i = 0; i < lenthOfInput; i++) {
      pads += "0";
    }
    String Input = pads.concat(InputHex);
    String oneB = Integer.toHexString(27);
    String shiftedBinary = Integer.toBinaryString(Integer.parseInt(Input, 2) << 1);
    if (shiftedBinary.length() > 8) {
      shiftedBinary = shiftedBinary.substring(1);
    }
    String shifted = Integer.toHexString(Integer.parseInt(shiftedBinary, 2));

    if (Input.substring(0, 1).equals("1")) {
      return exclusiveOr(shifted, oneB);
    } else
      return shifted;
  }

  /**
   * S_BOX static variable which is used for s-box transformations and used in
   * aesBox
   */
  private static final String[][] S_BOX = {
      {"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76"},
      {"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0"},
      {"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15"},
      {"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75"},
      {"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84"},
      {"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF"},
      {"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8"},
      {"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2"},
      {"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73"},
      {"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB"},
      {"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79"},
      {"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08"},
      {"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},
      {"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E"},
      {"E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF"},
      {"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"}};

  /**
   * R_CON static variable which is used for r-con transformations and used in
   * aesRcon
   */

  private static final String[][] R_CON = {
      {"8D", "01", "02", "04", "08", "10", "20", "40", "80", "1B", "36", "6C", "D8", "AB", "4D", "9A"},
      {"2F", "5E", "BC", "63", "C6", "97", "35", "6A", "D4", "B3", "7D", "FA", "EF", "C5", "91", "39"},
      {"72", "E4", "D3", "BD", "61", "C2", "9F", "25", "4A", "94", "33", "66", "CC", "83", "1D", "3A"},
      {"74", "E8", "CB", "8D", "01", "02", "04", "08", "10", "20", "40", "80", "1B", "36", "6C", "D8"},
      {"AB", "4D", "9A", "2F", "5E", "BC", "63", "C6", "97", "35", "6A", "D4", "B3", "7D", "FA", "EF"},
      {"C5", "91", "39", "72", "E4", "D3", "BD", "61", "C2", "9F", "25", "4A", "94", "33", "66", "CC"},
      {"83", "1D", "3A", "74", "E8", "CB", "8D", "01", "02", "04", "08", "10", "20", "40", "80", "1B"},
      {"36", "6C", "D8", "AB", "4D", "9A", "2F", "5E", "BC", "63", "C6", "97", "35", "6A", "D4", "B3"},
      {"7D", "FA", "EF", "C5", "91", "39", "72", "E4", "D3", "BD", "61", "C2", "9F", "25", "4A", "94"},
      {"33", "66", "CC", "83", "1D", "3A", "74", "E8", "CB", "8D", "01", "02", "04", "08", "10", "20"},
      {"40", "80", "1B", "36", "6C", "D8", "AB", "4D", "9A", "2F", "5E", "BC", "63", "C6", "97", "35"},
      {"6A", "D4", "B3", "7D", "FA", "EF", "C5", "91", "39", "72", "E4", "D3", "BD", "61", "C2", "9F"},
      {"25", "4A", "94", "33", "66", "CC", "83", "1D", "3A", "74", "E8", "CB", "8D", "01", "02", "04"},
      {"08", "10", "20", "40", "80", "1B", "36", "6C", "D8", "AB", "4D", "9A", "2F", "5E", "BC", "63"},
      {"C6", "97", "35", "6A", "D4", "B3", "7D", "FA", "EF", "C5", "91", "39", "72", "E4", "D3", "BD"},
      {"61", "C2", "9F", "25", "4A", "94", "33", "66", "CC", "83", "1D", "3A", "74", "E8", "CB", "8D"}};
}
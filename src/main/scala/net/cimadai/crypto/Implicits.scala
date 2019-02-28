package net.cimadai.crypto

object Implicits {
  implicit class ImplicitByteArray(bytes: Array[Byte]) {
    /**
      * Converts an hexadecimal representation to n [Array[Byte]].
      * @throws IllegalArgumentException
      */
    implicit def hexa: String =
      bytes
        .map(byte => "%02x".format(byte))
        .mkString
  }

  implicit class ImplicitHexaString(s: String) {
    /**
      * Converts an [Array[Byte]] to an hexadecimal representation.
      * @throws NumberFormatException
      */
    implicit def bytes: Array[Byte] =
      s.sliding(1,1).toArray
        .map(pair => Integer.parseInt(pair, 16).toByte)
  }
}

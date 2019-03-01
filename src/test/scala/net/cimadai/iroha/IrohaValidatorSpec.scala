package net.cimadai.iroha

import utest._

object IrohaValidatorSpec extends TestSuite {
  import scala.util.Try

  val tests = this {
    "Domain names: Should reject invalid input: "- {
      val o = new Object with Iroha.Validation
      "abc"              -{ checkFailure(o.parseDomainName) }
    }
    "Domain names: Should accept valid input: "-{
      val o = new Object with Iroha.Validation
      "abc.xx"           -{ checkSuccess(o.parseDomainName) }
      "abc.xx.yy"        -{ checkSuccess(o.parseDomainName) }
      "abc.xx.yy.zz"     -{ checkSuccess(o.parseDomainName) }
      "xn--abc.xx.yy.zz" -{ checkSuccess(o.parseDomainName) }
    }

    //TODO: "Peer address: Should reject invalid input: "- {
    //TODO:   val o = new Object with Iroha.Validation
    //TODO:   ""                     -{ checkFailure(o.parsePeerAddress) }
    //TODO:   "0"                    -{ checkFailure(o.parsePeerAddress) }
    //TODO:   "0.0"                  -{ checkFailure(o.parsePeerAddress) }
    //TODO:   "0.0.0"                -{ checkFailure(o.parsePeerAddress) }
    //TODO:   "0.0.0.0"              -{ checkFailure(o.parsePeerAddress) }
    //TODO:   "invalid.example.com"              -{ checkFailure(o.parsePeerAddress) }
    //TODO: }
    //TODO:
    //TODO: "Peer address: Should accept valid input: "-{
    //TODO:   val o = new Object with Iroha.Validation
    //TODO:   // IPv4
    //TODO:   "127.0.0.1"                           -{ checkFailure(o.parsePeerAddress) }
    //TODO:   "192.168.0.1"                         -{ checkFailure(o.parsePeerAddress) }
    //TODO:   "172.10.20.30"                        -{ checkFailure(o.parsePeerAddress) }
    //TODO:   "10.10.20.30"                         -{ checkFailure(o.parsePeerAddress) }
    //TODO:   // IPv6
    //TODO:   "::1"                                 -{ checkSuccess(o.parsePeerAddress) }
    //TODO:   "fdfa:ffee:1a8b::1"                   -{ checkSuccess(o.parsePeerAddress) }
    //TODO:   "2001:470:1f1c:b61::2"                -{ checkSuccess(o.parsePeerAddress) }
    //TODO:   "2001:470:195e:0:be5f:f4ff:fef9:b2f6" -{ checkSuccess(o.parsePeerAddress) }
    //TODO:   // Should be able to resolve these names
    //TODO:   "localhost"                           -{ checkFailure(o.parsePeerAddress) }
    //TODO:   "blog.rgomes.info"                    -{ checkSuccess(o.parsePeerAddress) }
    //TODO:   "terra.mathminds.io"                  -{ checkSuccess(o.parsePeerAddress) }
    //TODO: }

    "Asset names: Should reject invalid input: "- {
      val o = new Object with Iroha.Validation
      ""                                  -{ checkFailure(o.parseAssetName) }
      "a23456789012345678901234567890123" -{ checkFailure(o.parseAssetName) }
      "$2345678901234567890123456789012"  -{ checkFailure(o.parseAssetName) }
      "silver.coin"                       -{ checkFailure(o.parseAssetName) }
    }
    "Asset names: Should accept valid input: "-{
      val o = new Object with Iroha.Validation
      "a2345678901234567890123456789012"  -{ checkSuccess(o.parseAssetName) }
      "A2345678901234567890123456789012"  -{ checkSuccess(o.parseAssetName) }
      "coin"                              -{ checkSuccess(o.parseAssetName) }
    }

    "Account names: Should reject invalid input: "- {
      val o = new Object with Iroha.Validation
      ""                                  -{ checkFailure(o.parseAccountName) }
      "a23456789012345678901234567890123" -{ checkFailure(o.parseAccountName) }
      "A2345678901234567890123456789012"  -{ checkFailure(o.parseAccountName) }
      "$2345678901234567890123456789012"  -{ checkFailure(o.parseAccountName) }
      "john.smith"                        -{ checkFailure(o.parseAccountName) }
    }
    "Account names: Should accept valid input: "-{
      val o = new Object with Iroha.Validation
      "a2345678901234567890123456789012"  -{ checkSuccess(o.parseAccountName) }
      "jsmith"                            -{ checkSuccess(o.parseAccountName) }
    }

    "Role names: Should reject invalid input: "- {
      val o = new Object with Iroha.Validation
      ""                                               -{ checkFailure(o.parseRoleName) }
      "a234567890123456789012345678901234567890123456" -{ checkFailure(o.parseRoleName) }
      "$23456789012345678901234567890123456789012345"  -{ checkFailure(o.parseRoleName) }
      "super.user"                                     -{ checkFailure(o.parseRoleName) }
    }
    "Role names: Should accept valid input: "-{
      val o = new Object with Iroha.Validation
      "a23456789012345678901234567890123456789012345"  -{ checkSuccess(o.parseRoleName) }
      "A23456789012345678901234567890123456789012345"  -{ checkSuccess(o.parseRoleName) }
      "superuser"                                      -{ checkSuccess(o.parseRoleName) }
    }

    "Amount: Should reject invalid input: "- {
      val o = new Object with Iroha.Validation
      ""          -{ checkFailure(o.parseAmount) }
      "-1.05"     -{ checkFailure(o.parseAmount) }
      "-0.0"      -{ checkFailure(o.parseAmount) }
      "Infinity"  -{ checkFailure(o.parseAmount) }
      "-Infinity" -{ checkFailure(o.parseAmount) }
      "+Infinity" -{ checkFailure(o.parseAmount) }
      "NaN"       -{ checkFailure(o.parseAmount) }
      "zero"      -{ checkFailure(o.parseAmount) }
    }
    "Amount: Should accept valid input: "-{
      val o = new Object with Iroha.Validation
      "0"         -{ checkSuccess(o.parseAmount) }
      "0.0"       -{ checkSuccess(o.parseAmount) }
      "1"         -{ checkSuccess(o.parseAmount) }
      "1.0"       -{ checkSuccess(o.parseAmount) }
    }

  }

  def checkSuccess(check: String => Try[String])
                  (implicit testPath: utest.framework.TestPath): Unit =
    assert(check(testPath.value.last).isSuccess)

  def checkFailure(check: String => Try[String])
                  (implicit testPath: utest.framework.TestPath): Unit =
    assert(check(testPath.value.last).isFailure)

}

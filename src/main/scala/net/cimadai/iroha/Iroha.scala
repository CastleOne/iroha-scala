package net.cimadai.iroha

/**
  * Copyright Daisuke SHIMADA, Richard Gomes -  All Rights Reserved.
  * https://github.com/cimadai/iroha-scala
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at
  *      http://www.apache.org/licenses/LICENSE-2.0
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */

object Iroha {
  import iroha.protocol.commands.Command
  import iroha.protocol.commands.Command.Command._
  import iroha.protocol.endpoint.{ToriiResponse, TxStatus, TxStatusRequest}
  import iroha.protocol.primitive._
  import iroha.protocol.queries.Query
  import iroha.protocol.transaction.Transaction
  import iroha.protocol.{commands, queries}
  import net.cimadai.crypto.{SHA3EdDSAParameter, SHA3EdDSAPrivateKey, SHA3EdDSAPublicKey}
  import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
  import net.i2p.crypto.eddsa.{EdDSAEngine, EdDSAPrivateKey, EdDSAPublicKey, Utils}
  import org.spongycastle.jcajce.provider.digest.SHA3
  import java.util.concurrent.atomic.AtomicLong

  private val queryCounter = new AtomicLong(1) //FIXME: code review

  case class SHA3Ed25519KeyPair(privateKey: SHA3EdDSAPrivateKey, publicKey: SHA3EdDSAPublicKey) {
    def toHex: Ed25519KeyPairHex = Ed25519KeyPairHex(privateKey.toPrivateKeyHex)
  }

  object SHA3Ed25519KeyPairHex {
    def apply (privateKeyHex: String): SHA3Ed25519KeyPairHex = {
      Ed25519KeyPairHex(Utils.hexToBytes(privateKeyHex))
    }
  }

  case class Ed25519KeyPairHex(privateKeyBytes: Array[Byte]) {
    private val sKey = new EdDSAPrivateKey(SHA3EdDSAPrivateKey(spec, privateKeyBytes))
    private val pKey = new EdDSAPublicKey(new EdDSAPublicKeySpec(sKey.toPublicKeyBytes, spec))

    val publicKey: String = sKey.toPublicKeyHex
    val privateKey: String = sKey.toPrivateKeyHex

    def toKey: Ed25519KeyPair =
      Ed25519KeyPair(sKey, pKey)
  }

  case class ToriiError(message: String, txStatus: TxStatus) extends Error(message)

  object ToriiError {
    def unapply(response: ToriiResponse): Option[ToriiError] = (response.errOrCmdName, response.txStatus) match {
      case (msg, TxStatus.STATELESS_VALIDATION_FAILED) => Some(ToriiError(s"Stateless Validation Failed: $msg", response.txStatus))
      case (msg, TxStatus.STATEFUL_VALIDATION_FAILED) => Some(ToriiError(s"Stateful Validation Failed: $msg", response.txStatus))
      case (msg, TxStatus.NOT_RECEIVED) => Some(ToriiError(s"Transaction Not Received: $msg", response.txStatus))
      case (msg, TxStatus.MST_EXPIRED) => Some(ToriiError(s"MST Expired: $msg", response.txStatus))
      case _ => None
    }
  }

  //--------------------------------------------------------------------------------------------------------------------

  trait Validation {
    import scala.util.{Failure, Success, Try}

    /** BLOCKING: Parse domain name according to RFC1035 and RFC5891 */
    def parseDomainName(value: String): Try[String] =
      sizeDomainName(value)
        .flatMap(value => validateDomainName(value))

    private def sizeDomainName(value: String): Try[String] =
      if(0 < value.length && value.length <= lengthDomainName)
        Success(value)
      else
        Failure(new IllegalArgumentException(s"domain name must be (0,${lengthDomainName}] characters: ${value}"))

    private def validateDomainName(value: String): Try[String] =
      value match {
        case regexDomainName(_*) => Success(value)
        case _                   => Failure(new IllegalArgumentException(s"invalid domain name: ${value}"))
      }

    //credits: Regular Expressions Cookbook by Steven Levithan, Jan Goyvaerts
    /** Regular expression which matches a domain name */
    val regexDomainName = "^(xn--)?((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}$".r

    /** Maximum length for a domain name */
    val lengthDomainName = 164

    //------------

    /** BLOCKING: Parse any IPv4 address or IPv6 address or domain name */
    def parsePeerAddress(value: String): Try[String] = ???


    /** BLOCKING: Parse IPv4 address */
    def parseIPv4(value: String): Try[String] =
      value match {
        case regexIPv4(_*) => Success(value)
        case _             => Failure(new IllegalArgumentException(s"invalid IPv4 address name: ${value}"))
      }

    /** BLOCKING: Parse IPv6 address */
    def parseIPv6(value: String): Try[String] =
      value match {
        case regexIPv6(_*) => Success(value)
        case _             => Failure(new IllegalArgumentException(s"invalid IPv4 address name: ${value}"))
      }

    //credits: Regular Expressions Cookbook by Steven Levithan, Jan Goyvaerts
    /** Regular expression which matches a IPv4 address */
    val regexIPv4 = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$".r


    //credits: Regular Expressions Cookbook by Steven Levithan, Jan Goyvaerts
    /** Regular expression which matches a IPv6 address */
    val regexIPv6 = "^(?:(?:(?:[A-F0-9]{1,4}:){6}|(?=(?:[A-F0-9]{0,4}:){0,6}(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$)(([0-9A-F]{1,4}:){0,5}|:)((:[0-9A-F]{1,4}){1,5}:|:))(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}|(?=(?:[A-F0-9]{0,4}:){0,7}[A-F0-9]{0,4}$)(([0-9A-F]{1,4}:){1,7}|:)((:[0-9A-F]{1,4}){1,7}|:))$".r

    //------------

    /** BLOCKING: Parse asset name */
    def parseAssetName(value: String): Try[String] =
      sizeAssetName(value)
        .flatMap(value => validateAssetName(value))

    private def sizeAssetName(value: String): Try[String] =
      if(0 < value.length && value.length <= lengthAssetName)
        Success(value)
      else
        Failure(new IllegalArgumentException(s"asset name must be (0,${lengthAssetName}] characters: ${value}"))

    private def validateAssetName(value: String): Try[String] =
      value match {
        case regexAssetName(_*) => Success(value)
        case _                  => Failure(new IllegalArgumentException(s"invalid asset name: ${value}"))
      }

    /** Regular expressions which matches an asset name */
    val regexAssetName = "^[a-zA-Z0-9]+$".r

    /** Maximum length for an asset name */
    val lengthAssetName = 32

    //------------

    /** BLOCKING: Parse account name */
    def parseAccountName(value: String): Try[String] =
      sizeAccountName(value)
        .flatMap(value => validateAccountName(value))

    private def sizeAccountName(value: String): Try[String] =
      if(0 < value.length && value.length <= lengthAccountName)
        Success(value)
      else
        Failure(new IllegalArgumentException(s"account name must be (0,${lengthAccountName}] characters: ${value}"))

    private def validateAccountName(value: String): Try[String] =
      value match {
        case regexAccountName(_*) => Success(value)
        case _                    => Failure(new IllegalArgumentException(s"invalid account name: ${value}"))
      }

    /** Regular expression which matches an account name */
    val regexAccountName = "^[a-z0-9_]+$".r

    /** Maximum length for an account name */
    val lengthAccountName = 32

    //----------

    /** BLOCKING: Parse role name */
    def parseRoleName(value: String): Try[String] =
      sizeRoleName(value)
        .flatMap(value => validateRoleName(value))

    private def sizeRoleName(value: String): Try[String] =
      if(0 < value.length && value.length <= lengthRoleName)
        Success(value)
      else
        Failure(new IllegalArgumentException(s"role name must be (0,${lengthRoleName}] characters: ${value}"))

    private def validateRoleName(value: String): Try[String] =
      value match {
        case regexRoleName(_*) => Success(value)
        case _                 => Failure(new IllegalArgumentException(s"invalid role name: ${value}"))
      }

    /** Regular expressions which matches a role name */
    val regexRoleName = "^[A-Za-z0-9]+$".r

    /** Maximum length for a role name */
    val lengthRoleName = 45

    //----------

    def parseAmount(value: BigDecimal): Try[BigDecimal] =
      if(value.doubleValue >= 0.0)
        Success(value)
      else
        Failure(new IllegalArgumentException(s"amount must be greater or equal zero: ${value}"))

    //----------

    /** BLOCKING: Parse description */
    def parseDescription(value: String): Try[String] =
      if(0 < value.length && value.length <= lengthDescription)
        Success(value)
      else
        Failure(new IllegalArgumentException(s"description must be (0,${lengthDescription}] characters: ${value}"))

    /** Maximum length for a transfer description */
    val lengthDescription = 64

  }

  //--------------------------------------------------------------------------------------------------------------------

  trait Display {
    def toString: String
  }

  trait Domain extends Display
  object Domain extends Validation {
    import monix.eval.Task
    import scala.util.Try

    private case class impl(value: String) extends Domain {
      override def toString: String = value
    }

    /** Asynchronously builds [Domain] from domain name */
    def apply(domain: String): Task[Domain] =
      Task.defer(
        Task.fromTry(
          parse(domain)))

    /** BLOCKING: builds [Domain] from domain name */
    def parse(domain: String): Try[Domain] =
      parseDomainName(domain)
        .map(domain => impl(domain))
  }

  trait Account extends Display
  object Account extends Validation {
    import monix.eval.Task
    import scala.util.Try

    private case class impl(value: String) extends Account {
      override def toString: String = value
    }

    /** Asynchronously builds [Account] from account name and domain name */
    def apply(account: String, domain: String): Task[Account] =
      Task.defer(
        Task.fromTry(
          parse(account, domain)))

    /** BLOCKING: builds [Account] from account name and domain name */
    def parse(account: String, domain: String): Try[Account] =
      for {
        _ <- parseAccountName(account)
        _ <- parseDomainName(domain)
      } yield {
        new impl(s"${account}@${domain}")
      }
  }

  trait Asset extends Display
  object Asset extends Validation {
    import monix.eval.Task
    import scala.util.Try

    private case class impl(value: String) extends Asset {
      override def toString: String = value
    }

    /** Asynchronously builds [Asset] from asset name and domain name */
    def apply(asset: String, domain: String): Task[Asset] =
      Task.defer(
        Task.fromTry(
          parse(asset, domain)))

    /** BLOCKING: builds [Asset] from asset name and domain name */
    def parse(asset: String, domain: String): Try[Asset] =
      for {
        _ <- parseAssetName(asset)
        _ <- parseDomainName(domain)
      } yield {
        new impl(s"${asset}#${domain}")
      }
  }

  trait Role extends Display
  object Role extends Validation {
    import monix.eval.Task
    import scala.util.Try

    private case class impl(value: String) extends Role  {
      override def toString: String = value
    }

    /** Asynchronously builds [Role] from role name */
    def apply(role: String): Task[Role] =
      Task.defer(
        Task.fromTry(
          parse(role)))

    /** BLOCKING: builds [Role] from role */
    def parse(role: String): Try[Role] =
      parseRoleName(role)
        .map(role => impl(role))
  }

  trait Amount extends Display
  object Amount extends Validation {
    import monix.eval.Task
    import scala.util.Try

    private case class impl(value: BigDecimal) extends Amount {
      override def toString: String = value.doubleValue.toString
    }

    /** Asynchronously builds [Amount] from [BigDecimal] */
    def apply(amount: BigDecimal): Task[Amount] =
      Task.defer(
        Task.fromTry(
          parse(amount)))

    /** BLOCKING: builds [Amount] from [BigDecimal] */
    def parse(amount: BigDecimal): Try[Amount] =
      parseAmount(amount)
        .map(amount => impl(amount))
  }

  trait Description extends Display
  object Description extends Validation {
    import monix.eval.Task
    import scala.util.Try

    private case class impl(value: String) extends Description {
      override def toString: String = value.toString
    }

    /** Asynchronously builds [Description] from [String] */
    def apply(description: String): Task[Description] =
      Task.defer(
        Task.fromTry(
          parse(description)))

    /** BLOCKING: builds [Description] from [String] */
    def parse(description: String): Try[Description] =
      parseDescription(description)
        .map(description => impl(description))
  }

  trait PeerAddress extends Display {
    def toPeer: Peer
  }
  object PeerAddress extends Validation {
    import monix.eval.Task
    import scala.util.Try

    private case class impl(address: String, publicKey: EdDSAPublicKey) extends PeerAddress {
      override def toString: String = address.toString
      override def toPeer: Peer = iroha.protocol.primitive.Peer(address, Utils.bytesToHex(publicKey.getAbyte))
    }

    /** Asynchronously builds [PeerAddress] from [Domain] and a [EdDSAPublicKey] */
    def apply(address: String, publicKey: EdDSAPublicKey): Task[PeerAddress] =
      Task.defer(
        Task.fromTry(
          parse(address, publicKey)))

    /** BLOCKING: builds [PeerAddress] from [Domain] and a [EdDSAPublicKey] */
    def parse(address: String, publicKey: EdDSAPublicKey): Try[PeerAddress] =
      parsePeerAddress(address)
        .map(address => impl(address, publicKey))
  }

  //--------------------------------------------------------------------------------------------------------------------

  private def withEd25519[T](f: EdDSAEngine => T): T = {
    val signature = new EdDSAEngine(new SHA3.Digest512())
    f(signature)
  }

  def createNewKeyPair(): Try[SHA3Ed25519KeyPair] = Try {
    val seed = Array.fill[Byte](32) {0x0}
    new scala.util.Random(new java.security.SecureRandom()).nextBytes(seed)
    val sKey = SHA3EdDSAPrivateKey(seed)
    val vKey = SHA3EdDSAPublicKey(sKey.toPublicKeyBytes)
    SHA3Ed25519KeyPair(sKey, vKey)
  }

  def createKeyPairFromHex(privateKeyHex: String): Ed25519KeyPair = {
    Ed25519KeyPairHex(privateKeyHex).toKey
  }

  def createKeyPairFromBytes(privateKeyBytes: Array[Byte]): Ed25519KeyPair = {
    Ed25519KeyPairHex(privateKeyBytes).toKey
  }

  def sign(keyPair: Ed25519KeyPair, message: Array[Byte]): Array[Byte] = {
    withEd25519 { ed25519 =>
      ed25519.initSign(keyPair.privateKey)
      ed25519.signOneShot(message)
    }
  }

  def verify(keyPair: Ed25519KeyPair, signature: Array[Byte], message: Array[Byte]): Boolean = {
    withEd25519 { ed25519 =>
      ed25519.initVerify(keyPair.publicKey)
      ed25519.verifyOneShot(message, signature)
    }
  }

  object CommandService {
    import IrohaImplicits._

    private def txHash(transaction: Transaction): Array[Byte] = {
      new SHA3.Digest256().digest(transaction.payload.get.toByteArray)
    }

    def createTransaction(creator: Account, creatorKeyPair: Ed25519KeyPair, commands: Seq[Command]): Transaction = {
      val createdTime = System.currentTimeMillis()

      val maybeReducedPayload = commands.headOption
        .map(_ => Transaction.Payload.ReducedPayload(commands, creator, createdTime, 1))

      val payload = Transaction.Payload(reducedPayload = maybeReducedPayload)

      val sha3_256 = new SHA3.Digest256()
      val hash = sha3_256.digest(payload.toByteArray)
      val sig = Signature(
        Utils.bytesToHex(creatorKeyPair.publicKey.toPublicKeyBytes),
        Utils.bytesToHex(Iroha.sign(creatorKeyPair, hash))
      )
      Transaction(Some(payload), Seq(sig))
    }

    def appendRole(account: Account, role: Role): Command =
      Command(AppendRole(commands.AppendRole(account, role)))

    def createRole(name: String, permissions: Seq[RolePermission]): Command =
      Command(CreateRole(commands.CreateRole(name, permissions)))

    def grantPermission(account: Account, permissions: GrantablePermission): Command =
      Command(GrantPermission(commands.GrantPermission(account, permissions)))

    def revokePermission(account: Account, permissions: GrantablePermission): Command =
      Command(RevokePermission(commands.RevokePermission(account, permissions)))

    def addPeer(peer: PeerAddress): Command =
      Command(AddPeer(commands.AddPeer(Some(peer))))

    def addSignatory(account: Account, publicKey: EdDSAPublicKey): Command =
      Command(AddSignatory(commands.AddSignatory(account, Utils.bytesToHex(publicKey.toPublicKeyBytes))))

    def createAccount(publicKey: EdDSAPublicKey, name: String, domain: Domain): Command =
      Command(CreateAccount(commands.CreateAccount(name, domain, Utils.bytesToHex(publicKey.toPublicKeyBytes))))

    def createAsset(name: String, domain: Domain, precision: Int): Command =
      Command(CreateAsset(commands.CreateAsset(name, domain, precision)))

    def createDomain(name: String, defaultRole: Role): Command =
      Command(CreateDomain(commands.CreateDomain(name, defaultRole)))

    def removeSignatory(account: Account, publicKey: EdDSAPublicKey): Command =
      Command(RemoveSignatory(commands.RemoveSignatory(account, Utils.bytesToHex(publicKey.toPublicKeyBytes))))

    def setAccountQuorum(account: Account, quorum: Int): Command =
      Command(SetAccountQuorum(commands.SetAccountQuorum(account, quorum)))

    def addAssetQuantity(asset: Asset, amount: Amount): Command =
      Command(AddAssetQuantity(commands.AddAssetQuantity(asset, amount)))

    def subtractAssetQuantity(asset: Asset, amount: Amount): Command =
      Command(SubtractAssetQuantity(commands.SubtractAssetQuantity(asset, amount)))

    def transferAsset(srcAccount: Account, dstAccount: Account,
                      asset: Asset, description: Description, amount: Amount): Command =
      Command(
        TransferAsset(
          commands.TransferAsset(
            srcAccount,
            dstAccount,
            asset,
            description,
            amount)))

    def txStatusRequest(transaction: Transaction): TxStatusRequest =
      TxStatusRequest(Utils.bytesToHex(Iroha.CommandService.txHash(transaction)))
  }

  object QueryService {

    private def createQuery(creator: Account, creatorKeyPair: Ed25519KeyPair, query: Query.Payload.Query): Query = {
      val createdTime = System.currentTimeMillis()

      val payload =
        Query.Payload(
          meta = Some(
            queries.QueryPayloadMeta(
              createdTime = createdTime,
              creatorAccountId = creator.toString,
              queryCounter = queryCounter.getAndIncrement()
            )),
          query = query
      )

      val sha3_256 = new SHA3.Digest256()
      val hash = sha3_256.digest(payload.toByteArray)
      val sig = Signature(
        Utils.bytesToHex(creatorKeyPair.publicKey.toPublicKeyBytes),
        Utils.bytesToHex(Iroha.sign(creatorKeyPair, hash))
      )
      Query(Some(payload), Some(sig))
    }

    def getAccount(creator: Account, creatorKeyPair: Ed25519KeyPair, account: Account): Query = {
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetAccount(queries.GetAccount(account.toString)))
    }

    def getSignatories(creator: Account, creatorKeyPair: Ed25519KeyPair, account: Account): Query = {
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetSignatories(queries.GetSignatories(account.toString)))
    }

    def getAccountTransactions(creator: Account, creatorKeyPair: Ed25519KeyPair, account: Account): Query = {
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetAccountTransactions(queries.GetAccountTransactions(account.toString)))
    }

    def getAccountAssetTransactions(creator: Account, creatorKeyPair: Ed25519KeyPair, account: Account, asset: Asset): Query = {
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetAccountAssetTransactions(queries.GetAccountAssetTransactions(account.toString, asset.toString)))
    }

    def getTransactions(creator: Account, creatorKeyPair: Ed25519KeyPair, txHashes: Seq[Array[Byte]]): Query = {
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetTransactions(queries.GetTransactions(txHashes.map(Utils.bytesToHex))))
    }

    def getAccountAssets(creator: Account, creatorKeyPair: Ed25519KeyPair, account: Account): Query = {
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetAccountAssets(queries.GetAccountAssets(account.toString)))
    }

    def getAccountDetail(creator: Account, creatorKeyPair: Ed25519KeyPair, account: Account): Query = {
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetAccount(queries.GetAccount(account.toString)))
    }

    def getRoles(creator: Account, creatorKeyPair: Ed25519KeyPair): Query = {
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetRoles(queries.GetRoles()))
    }

    def getRolePermissions(creator: Account, creatorKeyPair: Ed25519KeyPair, role: Role): Query = {
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetRolePermissions(queries.GetRolePermissions(role.toString)))
    }

    def getAssetInfo(creator: Account, creatorKeyPair: Ed25519KeyPair, asset: Asset): Query = {
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetAssetInfo(queries.GetAssetInfo(asset.toString)))
    }

    def getPendingTransactions(creator: Account, creatorKeyPair: Ed25519KeyPair): Query = {
      createQuery(creator, creatorKeyPair, Query.Payload.Query.GetPendingTransactions(queries.GetPendingTransactions()))
    }
  }

  sealed trait MatchedResponse

  object MatchedResponse {
    import iroha.protocol.{qry_responses => Responses}
    case class AccountAssetsResponse(response: Responses.AccountAssetResponse) extends MatchedResponse
    case class AccountDetailResponse(response: Responses.AccountDetailResponse) extends MatchedResponse
    case class AccountResponse(response: Responses.AccountResponse) extends MatchedResponse
    case class ErrorResponse(response: Responses.ErrorResponse) extends MatchedResponse
    case class SignatoriesResponse(response: Responses.SignatoriesResponse) extends MatchedResponse
    case class TransactionsResponse(response: Responses.TransactionsResponse) extends MatchedResponse
    case class AssetResponse(response: Responses.AssetResponse) extends MatchedResponse
    case class RolesResponse(response: Responses.RolesResponse) extends MatchedResponse
    case class RolePermissionsResponse(response: Responses.RolePermissionsResponse) extends MatchedResponse
  }

  object QueryResponse {
    import MatchedResponse._
    import iroha.protocol.qry_responses.QueryResponse

    def unapply(arg: QueryResponse): Option[MatchedResponse] = arg.response match {
      case r if r.isAccountAssetsResponse => arg.response.accountAssetsResponse.map(AccountAssetsResponse.apply)
      case r if r.isAccountDetailResponse => arg.response.accountDetailResponse.map(AccountDetailResponse.apply)
      case r if r.isAccountResponse => arg.response.accountResponse.map(AccountResponse.apply)
      case r if r.isErrorResponse => arg.response.errorResponse.map(ErrorResponse.apply)
      case r if r.isSignatoriesResponse => arg.response.signatoriesResponse.map(SignatoriesResponse.apply)
      case r if r.isTransactionsResponse => arg.response.transactionsResponse.map(TransactionsResponse.apply)
      case r if r.isAssetResponse => arg.response.assetResponse.map(AssetResponse.apply)
      case r if r.isRolesResponse => arg.response.rolesResponse.map(RolesResponse.apply)
      case r if r.isRolePermissionsResponse => arg.response.rolePermissionsResponse.map(RolePermissionsResponse.apply)
      case _ => None
    }
  }
}

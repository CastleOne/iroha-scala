organization in ThisBuild := "org.hyperledger"
scalaVersion in ThisBuild := "2.12.8"
licenses in ThisBuild += ("Apache-2.0", url("https://www.apache.org/licenses/LICENSE-2.0.html"))


val versions = new {
  val scalapbc = scalapb.compiler.Version.scalapbVersion
  val grpc = scalapb.compiler.Version.grpcJavaVersion
  val spongyCastle = "1.58.0.0"
  val i2p          = "0.2.0"
  val monix        = "3.0.0-RC2"
  val utest        = "0.6.6"
}

lazy val librarySettings: Seq[Setting[_]] =
  Seq(
    libraryDependencies ++=
      Seq(
        "io.grpc"                           %  "grpc-netty"           % versions.grpc,
        "com.thesamet.scalapb"              %% "scalapb-runtime-grpc" % versions.scalapbc,
        "com.thesamet.scalapb"              %% "scalapb-runtime-grpc" % versions.scalapbc % "protobuf",
        "com.madgag.spongycastle"           %  "bcpg-jdk15on"         % versions.spongyCastle,
        "net.i2p.crypto"                    %  "eddsa"                % versions.i2p,
        "io.monix"                          %% "monix"                % versions.monix,
        "com.lihaoyi"                       %% "utest"                % versions.utest      % "test",
      )
  )

lazy val compilerSettings: Seq[Setting[_]] =
  Seq(
    javacOptions ++= Seq(
      "-source", "1.8", 
      "-target", "1.8", 
      "-encoding", "UTF-8",
    ),
    scalacOptions ++= Seq(
      "-target:jvm-1.8",
      "-encoding", "UTF-8",
      "-unchecked",
      "-deprecation",
      "-Xfuture",
      "-Yno-adapted-args",
      "-Ywarn-dead-code",
      "-Ywarn-numeric-widen",
      "-Ywarn-value-discard",
      "-Ywarn-unused",
    ),
  )

lazy val testSettings: Seq[Setting[_]] =
  Seq(
    fork in Test := true,
  )
  
lazy val publishSettings: Seq[Setting[_]] =
  Seq(
    publishMavenStyle := false,
    publishArtifact in Test := false,
    pomIncludeRepository := { _ => false },
    //FIXME useGpg in xxxGlobalScope := true
    //TODO: bintrayRepository := "iroha-scala",
    //TODO: bintrayOrganization in bintray := None,
  )

lazy val grpcSettings: Seq[Setting[_]] =
  Seq(
    PB.targets in Compile :=
      Seq(
        scalapb.gen() -> (sourceManaged in Compile).value,
      )
  )


lazy val irohaScala = (project in file("."))
  .settings(
    name := "iroha-scala",
  )
  .settings(librarySettings: _*)
  .settings(compilerSettings: _*)
  .settings(testSettings: _*)
  .settings(grpcSettings: _*)
  .enablePlugins(ProtocPlugin)

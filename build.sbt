organization := "com.github.losizm"
name := "little-security"
version := "0.1.0"

description := "The Scala library that adds a little security to applications"
homepage := Some(url("https://github.com/losizm/little-security"))
licenses := List("Apache License, Version 2" -> url("http://www.apache.org/licenses/LICENSE-2.0.txt"))

scalaVersion := "2.13.2"
scalacOptions ++= Seq("-deprecation", "-feature", "-Xcheckinit")
crossScalaVersions := Seq("2.12.11")

Compile / unmanagedSourceDirectories += {
  (Compile / sourceDirectory).value / s"scala-${scalaBinaryVersion.value}"
}

libraryDependencies += "org.scalatest" %% "scalatest" % "3.1.1" % "test"

developers := List(
  Developer(
    id    = "losizm",
    name  = "Carlos Conyers",
    email = "carlos.conyers@hotmail.com",
    url   = url("https://github.com/losizm")
  )
)

scmInfo := Some(
  ScmInfo(
    url("https://github.com/losizm/little-security"),
    "scm:git@github.com:losizm/little-security.git"
  )
)

publishMavenStyle := true

publishTo := {
  val nexus = "https://oss.sonatype.org"
  isSnapshot.value match {
    case true  => Some("snaphsots" at s"$nexus/content/repositories/snapshots")
    case false => Some("releases" at s"$nexus/service/local/staging/deploy/maven2")
  }
}

pomIncludeRepository := (_ => false)

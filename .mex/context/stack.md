---
name: stack
description: Current platform and build boundary.
triggers: [Java, Maven, Bukkit, Velocity, BungeeCord]
last_updated: 2026-09-20
---

# Platform boundary

The single nested Maven project targets Java 21 and produces a plugin artifact with Bukkit, BungeeCord, and Velocity entry points. CI uses `mvn -B -f VotifierPlus/pom.xml package`. Inspect current POM and plugin descriptors for exact platform/version support. MEX 0.8.2 has no Java Code Graph here. Source: `VotifierPlus/pom.xml`, `.github/workflows/maven.yml`.

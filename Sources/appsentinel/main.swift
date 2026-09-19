import Foundation

// Entry point implemented in CLI.swift; kept here so SwiftPM recognizes
// `appsentinel` as a proper executable target from the start.
CLIEntryPoint.run(arguments: Array(CommandLine.arguments.dropFirst()))

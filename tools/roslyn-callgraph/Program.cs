using Microsoft.Build.Locator;

if (args.Length < 2)
{
    Console.Error.WriteLine("Usage: roslyn-callgraph <solution-or-project-path> <output-json-path>");
    return 1;
}

// Must run before any Microsoft.CodeAnalysis.MSBuild type is touched by the
// JIT. CallGraphExtractor lives in a separate class so the runtime doesn't
// need to resolve MSBuild-dependent types until RunAsync is actually called.
MSBuildLocator.RegisterDefaults();

return await CallGraphExtractor.RunAsync(args[0], args[1]);

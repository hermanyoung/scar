using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.MSBuild;

/// <summary>
/// Extracts method-level call edges from a .sln or .csproj using Roslyn's
/// semantic model, and writes them as JSON for SCAR's call_graph.py to
/// consume. This is the only component of SCAR that resolves C# symbols
/// with full semantic accuracy (tree-sitter, used elsewhere for structural
/// metrics, has no type/overload resolution).
/// </summary>
public static class CallGraphExtractor
{
    public static async Task<int> RunAsync(string projectOrSolutionPath, string outputPath)
    {
        using var workspace = MSBuildWorkspace.Create();
        workspace.WorkspaceFailed += (_, e) =>
            Console.Error.WriteLine($"warning: {e.Diagnostic.Message}");

        var projects = new List<Project>();
        if (projectOrSolutionPath.EndsWith(".sln", StringComparison.OrdinalIgnoreCase))
        {
            var solution = await workspace.OpenSolutionAsync(projectOrSolutionPath);
            projects.AddRange(solution.Projects);
        }
        else
        {
            var project = await workspace.OpenProjectAsync(projectOrSolutionPath);
            projects.Add(project);
        }

        var projectRoot = Path.GetDirectoryName(Path.GetFullPath(projectOrSolutionPath)) ?? ".";
        var edges = new List<CallEdgeRecord>();

        foreach (var project in projects)
        {
            var compilation = await project.GetCompilationAsync();
            if (compilation is null)
                continue;

            foreach (var document in project.Documents)
            {
                var tree = await document.GetSyntaxTreeAsync();
                if (tree is null)
                    continue;

                var root = await tree.GetRootAsync();
                var semanticModel = compilation.GetSemanticModel(tree);

                foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
                {
                    var callerSymbol = GetEnclosingSymbol(invocation, semanticModel);
                    if (callerSymbol is null)
                        continue;

                    var calleeInfo = semanticModel.GetSymbolInfo(invocation);
                    var calleeSymbol = calleeInfo.Symbol ?? calleeInfo.CandidateSymbols.FirstOrDefault();
                    if (calleeSymbol is null)
                        continue;

                    var lineSpan = tree.GetLineSpan(invocation.Span);
                    var filePath = document.FilePath ?? tree.FilePath;
                    var relativePath = Path.GetRelativePath(projectRoot, filePath).Replace('\\', '/');

                    bool isVirtual = false;
                    bool isExtension = false;
                    if (calleeSymbol is IMethodSymbol methodSymbol)
                    {
                        isVirtual = methodSymbol.IsVirtual || methodSymbol.IsOverride || methodSymbol.IsAbstract;
                        isExtension = methodSymbol.IsExtensionMethod;
                    }

                    edges.Add(new CallEdgeRecord(
                        Caller: FormatSymbol(callerSymbol),
                        Callee: FormatSymbol(calleeSymbol),
                        File: relativePath,
                        Line: lineSpan.StartLinePosition.Line + 1,
                        IsVirtual: isVirtual,
                        IsExtension: isExtension));
                }
            }
        }

        var json = JsonSerializer.Serialize(edges, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        });
        await File.WriteAllTextAsync(outputPath, json);
        Console.WriteLine($"Wrote {edges.Count} call edges to {outputPath}");
        return 0;
    }

    /// <summary>Walk up the syntax tree to find the declared method/property/ctor containing this call site.</summary>
    private static ISymbol? GetEnclosingSymbol(SyntaxNode node, SemanticModel semanticModel)
    {
        for (var current = node.Parent; current is not null; current = current.Parent)
        {
            if (current is MethodDeclarationSyntax or ConstructorDeclarationSyntax or
                PropertyDeclarationSyntax or AccessorDeclarationSyntax or
                LocalFunctionStatementSyntax)
            {
                var symbol = semanticModel.GetDeclaredSymbol(current);
                if (symbol is not null)
                    return symbol;
            }
        }
        return null;
    }

    private static readonly SymbolDisplayFormat QualifiedFormat = SymbolDisplayFormat.FullyQualifiedFormat
        .WithMemberOptions(SymbolDisplayMemberOptions.IncludeContainingType)
        .WithGenericsOptions(SymbolDisplayGenericsOptions.None)
        .WithMiscellaneousOptions(SymbolDisplayMiscellaneousOptions.None);

    private static string FormatSymbol(ISymbol symbol)
    {
        var display = symbol.ToDisplayString(QualifiedFormat);
        return display.StartsWith("global::", StringComparison.Ordinal)
            ? display["global::".Length..]
            : display;
    }
}

public sealed record CallEdgeRecord(
    string Caller, string Callee, string File, int Line, bool IsVirtual, bool IsExtension);

param(
    [string]$GhidraRoot = 'D:\ghidra_12.1.4_PUBLIC',
    [string]$JavaExecutable = 'C:\Program Files\Java\jdk-21.0.12.1\bin\java.exe'
)
$ErrorActionPreference = 'Stop'
$researchRoot = $PSScriptRoot
$projectDirectory = Join-Path $researchRoot 'ghidra-projects'
$outputDirectory = Join-Path $researchRoot 'ghidra-targeted-output'
$homeDirectory = Join-Path $researchRoot 'ghidra-home'
$settingsDirectory = Join-Path $researchRoot 'ghidra-settings'
$cacheDirectory = Join-Path $researchRoot 'ghidra-cache'
$tempDirectory = Join-Path $researchRoot 'ghidra-temp'
foreach ($directory in @($projectDirectory, $outputDirectory, $homeDirectory, $settingsDirectory, $cacheDirectory, $tempDirectory)) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
}
$ghidraArguments = @(
    '-Xmx2G', '-Xshare:off', '-XX:ParallelGCThreads=2', '-XX:CICompilerCount=2',
    '-Djava.system.class.loader=ghidra.GhidraClassLoader', '-Dfile.encoding=UTF8',
    '-Duser.country=US', '-Duser.language=en', '-Djava.awt.headless=true',
    '-Dlog4j.skipJansi=true', '--enable-native-access=ALL-UNNAMED',
    "-Duser.home=$homeDirectory", "-Dapplication.settingsdir=$settingsDirectory",
    "-Dapplication.cachedir=$cacheDirectory", "-Dapplication.tempdir=$tempDirectory", "-Djava.io.tmpdir=$tempDirectory",
    '-Djavax.xml.accessExternalDTD=', '-Djavax.xml.accessExternalSchema=', '-Djavax.xml.accessExternalStylesheet=',
    '-cp', (Join-Path $ghidraRoot 'Ghidra\Framework\Utility\lib\Utility.jar'),
    'ghidra.Ghidra', 'ghidra.app.util.headless.AnalyzeHeadless',
    $projectDirectory, 'TatoTargeted',
    '-import', (Join-Path $researchRoot 'samples\windows-extracted\Tatotalk.exe'),
    '-noanalysis', '-max-cpu', '2',
    '-loader', 'PeLoader', '-loader-loadLibraries', 'false', '-loader-ordinalLookup', 'false', '-loader-parseCliHeaders', 'false',
    '-scriptPath', (Join-Path $researchRoot 'ghidra-scripts'),
    '-postScript', 'TatoTargetedDecompile.java', $outputDirectory, (Join-Path $researchRoot 'windows-instruction-starts.csv'),
    '-log', (Join-Path $researchRoot 'ghidra-headless.log'),
    '-scriptlog', (Join-Path $researchRoot 'ghidra-script.log')
)
& $javaExecutable @ghidraArguments
exit $LASTEXITCODE

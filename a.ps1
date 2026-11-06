Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' |
ForEach-Object {
    Get-ChildItem ($_.DeviceID + '\') -Recurse -File -Force -ErrorAction SilentlyContinue
} |
ForEach-Object {
    $path = $_.FullName
    $reader = $null
    try {
        $reader = [IO.BinaryReader]::new(
            [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
        )
        $stream = $reader.BaseStream
        if ($stream.Length -lt 64) { return }
        if ($reader.ReadUInt16() -ne 0x5A4D) { return }

        $stream.Position = 0x3C
        $offset = $reader.ReadInt32()
        if ($offset -lt 64 -or $offset -gt ($stream.Length - 24)) { return }

        $stream.Position = $offset
        if ($reader.ReadUInt32() -eq 0x00004550) {
            Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop |
                Where-Object Status -eq 'NotSigned' |
                Select-Object -ExpandProperty Path
        }
    }
    catch { Write-Warning "${path}: $($_.Exception.Message)" }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
    }
}
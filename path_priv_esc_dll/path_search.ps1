Write-Host "[+] Search for vulnerable directories, that are part of the global path variable ...`n"
$vuln_dirs = 0

$path_env = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "Path").Path
$path_env -split ";" | foreach {
	if($_) {
		New-Item -Path "$($_)" -Name "SprintCSP.dll" -ItemType "file" -Value "" -Force -ErrorAction SilentlyContinue | Out-Null
		if(Test-Path -Path "$($_)\SprintCSP.dll") {
			Remove-Item -Path "$($_)\SprintCSP.dll" -Force -ErrorAction SilentlyContinue | Out-Null
			$vuln_dirs++
			Write-Host "[+] Target $($vuln_dirs): $($_)"
		}
	}
}

if($vuln_dirs -gt 0) {
	Write-Host "`n[+] At least one vulnerable directory was found! Let's go ..."
} else {
	Write-Host "[-] No vulnerable directories found!"
}

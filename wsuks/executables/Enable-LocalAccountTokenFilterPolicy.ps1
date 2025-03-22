# Ensure LocalAccountTokenFilterPolicy is set to 1
# Original src: https://github.com/Orange-Cyberdefense/GOAD/blob/88ef39d8b6b7cfd08e0ae7e92be59bc9fecf3280/vagrant/ConfigureRemotingForAnsible.ps1#L297-L309
$token_path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';
$token_prop_name = 'LocalAccountTokenFilterPolicy';
$token_value = $(Get-Item -Path $token_path).GetValue($token_prop_name, $null);
$token_value = if ($null -eq $token_value) { 'Not set' } else { $token_value };
Write-Output ('Value of LocalAccountTokenFilterPolicy: ' + $token_value);
if ($token_value -ne 1) {
    if ('Not set' -ne $token_value) {
        Remove-ItemProperty -Path $token_path -Name $token_prop_name;
    }
    New-ItemProperty -Path $token_path -Name $token_prop_name -Value 1 -PropertyType DWORD > $null;
}
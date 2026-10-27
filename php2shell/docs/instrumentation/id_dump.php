<?php
$ps_off = hexdec($argv[1]);
foreach (glob('/proc/[0-9]*') as $d) {
    $cmd = @file_get_contents("$d/cmdline");
    if ($cmd === false || strpos($cmd, 'apache2') === false) continue;
    $maps = @file("$d/maps"); if (!$maps) continue;
    $lib = null;
    foreach ($maps as $l) if ($lib === null && strpos($l, 'libphp') !== false) $lib = hexdec(substr($l,0,strpos($l,'-')));
    if ($lib === null) continue;
    $f=@fopen("$d/mem",'rb'); if(!$f) continue;
    fseek($f,$lib+$ps_off); $data=fread($f,0x40); fclose($f);
    $id=unpack('P',substr($data,0x10,8))[1];
    printf("%s lib=0x%x id=0x%x\n",$d,$lib,$id);
}

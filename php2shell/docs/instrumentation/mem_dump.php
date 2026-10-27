<?php
$ps_off=hexdec($argv[1]);
foreach (glob('/proc/[0-9]*') as $d) {
  $cmd=@file_get_contents("$d/cmdline"); if($cmd===false||strpos($cmd,'apache2')===false) continue;
  $maps=@file("$d/maps"); if(!$maps) continue; $lib=null; $chunk=null;
  foreach($maps as $l){
    if($lib===null && strpos($l,'libphp')!==false) $lib=hexdec(substr($l,0,strpos($l,'-')));
    if(preg_match('/^([0-9a-f]+)-([0-9a-f]+)\s+rw-p\s+/',$l,$m)){ $s=hexdec($m[1]); $e=hexdec($m[2]); if($e-$s===0x200000 && $chunk===null) $chunk=$s; }
  }
  if($lib===null||$chunk===null) continue;
  $f=@fopen("$d/mem",'rb'); if(!$f) continue;
  fseek($f,$lib+$ps_off); $ps=fread($f,0x200);
  $r0=unpack('P',substr($ps,0x150,8))[1];
  if($r0<$chunk||$r0>=$chunk+0x200000){continue;}
  fseek($f,$r0); $ref=fread($f,0x20);
  $r1=unpack('P',substr($ref,0x08,8))[1];
  printf("%s r0=0x%x rel0=0x%x r1=0x%x rel1=0x%x\n",$d,$r0,$r0-$chunk,$r1,$r1-$chunk);
  if($r1>=$chunk&&$r1<$chunk+0x200000){
    fseek($f,$r1); $arr=fread($f,0x40);
    for($i=0;$i<0x40;$i+=8) printf("  r1+0x%02x %s\n",$i,bin2hex(substr($arr,$i,8)));
  }
  fclose($f);
}

#!/usr/bin/php
<?php
////////////////////////////////////////////////////////////////////////////////
// Given a server name as a first argument returns one of these strings:
// - OFFLINE if the server does not respond on port 22 (SSH)
// - xx.xx where xx.xx represents the 1min load of the target machine. This
//   is obtained by connecting to port 5666 (nagios, nrpe).
// - ONLINE if no load info was obtainable but port 22 was open.
//
// Note:
// Python/go don't offer the ADH cipher that's needed for nrpe. Hence using php.
////////////////////////////////////////////////////////////////////////////////

// Timeout in seconds. We can't waste time. User wants to get connected...
define('TIMEOUT', 0.1);

// Sigh, only ints...
set_time_limit(1);
ini_set('default_socket_timeout', 0.1);

// FROM:
// http://blog.cactiusers.org/2012/02/18/nagios-nrpe-client-via-php/
function sendcmd($data, $f) {
  for ($a = strlen($data) ; $a < 1024; $a++) {
    $data .= "\x00";
  }
  $data .= "SR";
  $res = pack("n", 2324);
  $packet = "\x00\x02\x00\x01";
  $crc = crc32($packet . "\x00\x00\x00\x00" . $res . $data);
  $packet .= pack("N", $crc) . $res . $data;
  stream_set_timeout($f, TIMEOUT);
  fputs($f, $packet, strlen($packet));
  stream_set_timeout($f, TIMEOUT); // Not sure if needed... php docs are stupid
  $data = fread($f, 8192);
  $data = substr($data, 8);
  return $data;
}

function get_load($server) {
  $context = stream_context_create();
  $result = stream_context_set_option($context, 'ssl', 'ciphers', 'ADH');
  // SO this timeout seems to not work at all... Ints are also not working. I hate php
  $f = @stream_socket_client("ssl://$server:5666", $errno, $errstr, TIMEOUT, STREAM_CLIENT_CONNECT, $context);
  $out = false;
  if ($f) {
    stream_set_timeout($f, TIMEOUT); // Not sure if needed... php docs are stupid
    $out = sendcmd("check_load", $f);
    fclose($f);
  }
  return $out;
}

function has_open_ssh_port($server) {
  $errno = 0;
  $errstr = '';
  $conn = @fsockopen($server, 22, $errno, $errstr, TIMEOUT);
  if( is_resource($conn) ) {
    fclose($conn);
    return true;
  } else {
    return false;
  }
}

if( count($argv) <= 1 ) {
  die("Please provide me with the server name or address as the first input argument");
}
// only argument is our server name (or IP)
$server = $argv[1];

if( !has_open_ssh_port($server) ) {
  die("OFFLINE");
}

$load = get_load($server);
if( $load === false ) {
  die("ONLINE");
}
// Extract the 1min load:
preg_match('/load1=([0-9.]+);/', $load, $matches);
if( count($matches) >=1 ) {
  die(doubleval($matches[1]));
} else {
  // This shouldn't happen but we can just return online then. No harm
  die("ONLINE");
}

?>

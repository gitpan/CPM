package CPM;

use strict;
no strict 'refs';
use warnings;
use vars qw($VERSION);

$VERSION=1.0_01;

use IO::Socket;
use Net::SNMP;
use Net::Address::IP::Local;
use Net::Ping;
use XML::Simple;

sub new{
  my $class=shift;
  my $self={@_};
   bless($self, $class);
   $self->_init;
   return $self;
}

sub _init{
  my $self=shift;
  my $testip=eval{$self->{address}=Net::Address::IP::Local->public};
  if($@){$self->{address}='127.0.0.1';}
  $self->{net}=$self->{address};
  $self->{net}=~s/\.\d*\Z//; # extract net from address
  $self->{xml}=XMLin('config.xml',('forcearray',['device']));
  $self->{url}=$self->{xml}->{call}.'?login='.$self->{xml}->{id}->{user}.'&nppas='.$self->{xml}->{id}->{pass};

  return $self;
}

sub saveconfig{
  my $self=shift;
  my $out=XML::Simple::XMLout($self->{xml},('keeproot',1,xmldecl=>'<?xml version="1.0" encoding="UTF-8"?>')) || die "can't XMLout: $!";

  open (OUTFILE, '>./config.xml') || die "can't open output file: $!";
  binmode(OUTFILE, ":utf8");
  print OUTFILE $out;
  close OUTFILE;
  return $self;
}

sub request
# Make a SNMP request to read any OID (i.e Serial and Model)
{
  my $self=shift;
  my $oid=shift;
  my %properties=@_; # rest of params by hash
  
  my $type='none';
  $type=$properties{'-type'} if defined;

  my $session=Net::SNMP->session(-hostname=>$self->{target});
  if (!defined($session)) {return "TimeOut";}
  my $result = $session->get_request( varbindlist => [$oid]);
  $session->close;
  if(!defined($result->{$oid})){return "UnknownOID";}
  else{
     if($type eq 'MAC')
     {
       $result->{$oid}=~s/\A0x//;
       $result->{$oid}=~s/.{2}/$&:/g;
       $result->{$oid}=~s/:\Z//;
       return uc($result->{$oid});
     }
     elsif($type eq 'SN')
     {
             if(length($result->{$oid})<5){return "UnknownOID";}
             elsif($result->{$oid}=~/X{5,}/){return "UnknownOID";}
             else{
                  if($result->{$oid}=~/0x.*/){$result->{$oid}=_hex2ascii($result->{$oid});}
                  return $result->{$oid};
             }
     }
     else{
             if($result->{$oid}=~/0x.*/){$result->{$oid}=_hex2ascii($result->{$oid});}
             return $result->{$oid};
     }
  }
}

sub requesttable
# Make a SNMP walk requests
{
  my $self=shift;
  my $baseoid=shift;
  # Start a sesion connect to the host
  my $session=Net::SNMP->session(-hostname=>$self->{target});
  if (!defined($session)) {return "TimeOut";}
  # make a get-request
  my $result = $session->get_table(-baseoid=>$baseoid);
  my $values=$session->var_bind_list;
  my @koids = keys(%{$values});
  my $string='';
  foreach my $v(@koids)
  {
   $string.=$result->{$v}.'. ';
  }
  $session->close;
  if($result)
  {
    return $string;
  }
  else
  {
    return "UnkownObject";
  }
}

sub _osocket
# Open a socket on the 9100 port looking for JetDirects
{
  my $self=shift;
  my $sock = new IO::Socket::INET (
             PeerAddr => $self->{target},
             PeerPort => '9100',
             Proto => 'tcp',
  );
  if(!defined $sock){return -1;}
  else {close($sock);return 1}
}

sub _ping
# Check by ping
{
  my $self=shift;
  my $ping = Net::Ping->new();
  #return $ping->ping($self->{target},1);
  return $ping->ping($self->{target});
}

sub _hex2ascii
# Translate Hex to Ascii removing 0x0115 HP character
{
  my $str=shift||return;
  $str=~s/0x0115//;
  $str=~s/([a-fA-F0-9]{2})/chr(hex $1)/eg;
  $str=~s/\A0x.{2}//;
  #And eliminate Non Printable Chars 
  my @chars = split(//,$str);
  $str="";
  foreach my $ch (@chars){
    if ((ord($ch) > 31) && (ord($ch) < 127)){ $str .= $ch; }
  }
  return $str;
}

sub checkip
# Check socket and its snmp for specific IP
{
  my $self=shift;
  my $ping=shift;

  if($self->_ping)
  {
  # If we find the 9100 open, then...
    if($self->_osocket>0){
      my ($sn,$trace)=$self->_getsn;
      return $sn;
    }
#   else {print "Ping but not socket\n";return 0;}
  }
#  else {print "No ping\n"; return 0;}
}

sub _getsn
# Try to identify the SN using the standard OIDs
{
  my $self=shift;
  my $value='U_O';
  
  if(($value=$self->request('.1.3.6.1.4.1.11.2.3.9.4.2.1.1.3.3.0',-type=>'SN')) ne 'UnknownOID'){return $value,'1-';}
  elsif(($value=$self->request('.1.3.6.1.2.1.43.5.1.1.17.1',-type=>'SN')) ne 'UnknownOID'){return $value,'2-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.1248.1.2.2.1.1.1.5.1',-type=>'SN')) ne 'UnknownOID'){return $value,'3-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.1347.43.5.1.1.28.1',-type=>'SN')) ne 'UnknownOID'){return $value,'4-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.2001.1.1.1.1.11.1.10.45.0',-type=>'SN')) ne 'UnknownOID'){return $value,'5-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.23.2.32.4.3.0',-type=>'SN')) ne 'UnknownOID'){return $value,'6-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.253.8.53.3.2.1.3.1',-type=>'SN')) ne 'UnknownOID'){return $value,'7-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.367.3.2.1.2.1.4.0',-type=>'SN')) ne 'UnknownOID'){return $value,'8-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.367.3.2.1.6.1.1.7.1',-type=>'SN')) ne 'UnknownOID'){return $value,'9-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.641.2.1.2.1.6.1',-type=>'SN')) ne 'UnknownOID'){return $value,'10-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.2435.2.3.9.4.2.1.5.5.1.0',-type=>'SN')) ne 'UnknownOID'){return $value,'11-';}

  elsif(($value=$self->request('.1.3.6.1.2.1.2.2.1.6.1',-type=>'MAC')) ne 'UnknownOID'){return $value,'12-';}
  elsif(($value=$self->request('.1.3.6.1.2.1.2.2.1.6.2',-type=>'MAC')) ne 'UnknownOID'){return $value,'13-';}
  return $value,'X-';
}

sub getgeneric
{
  my $self=shift;
  my $host; # structure to store the results (if any)
  my $value='';
  
  ($host->{SN},$host->{TRACE})=$self->_getsn;
  
  $host->{TOTAL}='U_O';
  if(($value=$self->request('.1.3.6.1.2.1.43.10.2.1.4.1.1')) ne 'UnknownOID'){$host->{TOTAL}=$value;$host->{TRACE}.='1-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.641.2.1.5.1.0')) ne 'UnknownOID'){$host->{TOTAL}=$value;$host->{TRACE}.='2-';}

  $host->{COLOR}='U_O';
  if(($value=$self->request('.1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.2.7.0')) ne 'UnknownOID'){$host->{COLOR}=$value;$host->{TRACE}.='1-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.1248.1.2.2.27.1.1.4.1.1')) ne 'UnknownOID'){$host->{COLOR}=$value;$host->{TRACE}.='2-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.1347.42.2.2.1.1.3.1.2')) ne 'UnknownOID'){$host->{COLOR}=$value;$host->{TRACE}.='3-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.253.8.53.13.2.1.6.1.20.33')) ne 'UnknownOID'){$host->{COLOR}=$value;$host->{TRACE}.='4-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.367.3.2.1.2.19.5.1.9.12')) ne 'UnknownOID'){$host->{COLOR}=$value;$host->{TRACE}.='5-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.367.3.2.1.2.19.5.1.9.13')) ne 'UnknownOID'){$host->{COLOR}=$value;$host->{TRACE}.='6-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.367.3.2.1.2.19.5.1.9.21')) ne 'UnknownOID'){$host->{COLOR}=$value;$host->{TRACE}.='7-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.367.3.2.1.2.19.5.1.9.5')) ne 'UnknownOID'){$host->{COLOR}=$value;$host->{TRACE}.='8-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.367.3.2.1.3.2.3.2.1.4.128.1')) ne 'UnknownOID'){$host->{COLOR}=$value;$host->{TRACE}.='9-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.641.2.1.5.3.0')) ne 'UnknownOID'){$host->{COLOR}=$value;$host->{TRACE}.='10-';}

  $host->{MC1}='100';
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.8.1.1')) ne 'UnknownOID'){$host->{MC1}=$value;$host->{TRACE}.='1-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.2001.1.1.1.1.100.3.1.1.4.1')) ne 'UnknownOID'){$host->{MC1}=$value;$host->{TRACE}.='2-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.367.3.2.1.2.20.2.2.1.9.2.3')) ne 'UnknownOID'){$host->{MC1}=$value;$host->{TRACE}.='3-';}
  if($host->{MC1}==0){$host->{MC1}=100;}

  $host->{CC1}='U_O';
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.9.1.1')) ne 'UnknownOID'){$host->{CC1}=$value;$host->{TRACE}.='1-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.2001.1.1.1.1.100.3.1.1.3.1')) ne 'UnknownOID'){$host->{CC1}=$value;$host->{TRACE}.='2-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.253.8.53.20.2.1.7.2.1.4.20.3')) ne 'UnknownOID'){$host->{CC1}=$value;$host->{TRACE}.='3-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.367.3.2.1.2.24.1.1.5.1')) ne 'UnknownOID'){$host->{CC1}=$value;$host->{TRACE}.='4-';}

  $host->{MC2}='100';
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.8.1.2')) ne 'UnknownOID'){$host->{MC2}=$value;$host->{TRACE}.='5-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.2001.1.1.1.1.100.3.1.1.4.2')) ne 'UnknownOID'){$host->{MC2}=$value;$host->{TRACE}.='6-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.367.3.2.1.2.20.2.2.1.9.2.3')) ne 'UnknownOID'){$host->{MC2}=$value;$host->{TRACE}.='7-';}
  if($host->{MC2}==0){$host->{MC2}=100;}

  $host->{CC2}='U_O';
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.9.1.2')) ne 'UnknownOID'){$host->{CC2}=$value;$host->{TRACE}.='1-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.2001.1.1.1.1.100.3.1.1.3.2')) ne 'UnknownOID'){$host->{CC2}=$value;$host->{TRACE}.='2-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.253.8.53.20.2.1.7.2.1.1.20.3')) ne 'UnknownOID'){$host->{CC2}=$value;$host->{TRACE}.='3-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.367.3.2.1.2.24.1.1.5.2')) ne 'UnknownOID'){$host->{CC2}=$value;$host->{TRACE}.='4-';}

  $host->{MC3}='100';
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.8.1.3')) ne 'UnknownOID'){$host->{MC3}=$value;$host->{TRACE}.='1-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.2001.1.1.1.1.100.3.1.1.4.3')) ne 'UnknownOID'){$host->{MC3}=$value;$host->{TRACE}.='2-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.367.3.2.1.2.20.2.2.1.9.2.3')) ne 'UnknownOID'){$host->{MC3}=$value;$host->{TRACE}.='3-';}
  if($host->{MC3}==0){$host->{MC3}=100;}

  $host->{CC3}='U_O';
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.9.1.3')) ne 'UnknownOID'){$host->{CC3}=$value;$host->{TRACE}.='1-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.2001.1.1.1.1.100.3.1.1.3.3')) ne 'UnknownOID'){$host->{CC3}=$value;$host->{TRACE}.='2-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.253.8.53.20.2.1.7.2.1.2.20.3')) ne 'UnknownOID'){$host->{CC3}=$value;$host->{TRACE}.='3-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.367.3.2.1.2.24.1.1.5.3')) ne 'UnknownOID'){$host->{CC3}=$value;$host->{TRACE}.='4-';}

  $host->{MC4}='100';
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.8.1.4')) ne 'UnknownOID'){$host->{MC4}=$value;$host->{TRACE}.='1-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.2001.1.1.1.1.100.3.1.1.4.4')) ne 'UnknownOID'){$host->{MC4}=$value;$host->{TRACE}.='2-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.367.3.2.1.2.20.2.2.1.9.2.3')) ne 'UnknownOID'){$host->{MC4}=$value;$host->{TRACE}.='3-';}
  if($host->{MC4}==0){$host->{MC4}=100;}

  $host->{CC4}='U_O';
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.9.1.4')) ne 'UnknownOID'){$host->{CC4}=$value;$host->{TRACE}.='1-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.2001.1.1.1.1.100.3.1.1.3.4')) ne 'UnknownOID'){$host->{CC4}=$value;$host->{TRACE}.='2-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.253.8.53.20.2.1.7.2.1.3.20.3')) ne 'UnknownOID'){$host->{CC4}=$value;$host->{TRACE}.='3-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.367.3.2.1.2.24.1.1.5.4')) ne 'UnknownOID'){$host->{CC4}=$value;$host->{TRACE}.='4-';}

  $host->{MC5}='100';
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.8.1.5')) ne 'UnknownOID'){$host->{MC5}=$value;$host->{TRACE}.='1-';}
  elsif(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.8.1.8')) ne 'UnknownOID'){$host->{MC5}=$value;$host->{TRACE}.='2-';}
  elsif(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.8.1.11')) ne 'UnknownOID'){$host->{MC5}=$value;$host->{TRACE}.='3-';}
  if($host->{MC5}==0){$host->{MC5}=100;}

  $host->{CC5}='U_O';
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.9.1.5')) ne 'UnknownOID'){$host->{CC5}=$value;$host->{TRACE}.='1-';}
  elsif(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.9.1.8')) ne 'UnknownOID'){$host->{CC5}=$value;$host->{TRACE}.='2-';}
  elsif(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.9.1.11')) ne 'UnknownOID'){$host->{CC5}=$value;$host->{TRACE}.='3-';}

  $host->{MC6}='100';
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.8.1.6')) ne 'UnknownOID'){$host->{MC6}=$value;$host->{TRACE}.='1-';}
  elsif(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.8.1.9')) ne 'UnknownOID'){$host->{MC6}=$value;$host->{TRACE}.='2-';}
  if($host->{MC6}==0){$host->{MC6}=100;}

  $host->{CC6}='U_O';
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.9.1.6')) ne 'UnknownOID'){$host->{CC6}=$value;$host->{TRACE}.='1-';}
  elsif(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.9.1.9')) ne 'UnknownOID'){$host->{CC6}=$value;$host->{TRACE}.='2-';}

  $host->{MC7}='100';
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.8.1.7')) ne 'UnknownOID'){$host->{MC7}=$value;$host->{TRACE}.='1-';}
  elsif(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.8.1.10')) ne 'UnknownOID'){$host->{MC7}=$value;$host->{TRACE}.='2-';}
  elsif(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.8.1.11')) ne 'UnknownOID'){$host->{MC7}=$value;$host->{TRACE}.='3-';}
  if($host->{MC7}==0){$host->{MC7}=100;}

  $host->{CC7}='U_O';
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.9.1.7')) ne 'UnknownOID'){$host->{CC7}=$value;$host->{TRACE}.='1-';}
  elsif(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.9.1.10')) ne 'UnknownOID'){$host->{CC7}=$value;$host->{TRACE}.='2-';}
  elsif(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.9.1.11')) ne 'UnknownOID'){$host->{CC7}=$value;$host->{TRACE}.='3-';}

  $host->{MODEL}='U_O';
  if(($value=$self->request('.1.3.6.1.2.1.25.3.2.1.3.1')) ne 'UnknownOID'){$host->{MODEL}=$value;$host->{TRACE}.='1-';}
  elsif(($value=$self->request('.1.3.6.1.2.1.1.1.0')) ne 'UnknownOID'){$host->{MODEL}=$value;$host->{TRACE}.='2-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.11.2.3.9.4.2.1.1.3.2.0')) ne 'UnknownOID'){$host->{MODEL}=$value;$host->{TRACE}.='3-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.1347.43.5.1.1.1.1')) ne 'UnknownOID'){$host->{MODEL}=$value;$host->{TRACE}.='4-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.2001.1.3.1.1.10.1.0')) ne 'UnknownOID'){$host->{MODEL}=$value;$host->{TRACE}.='5-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.23.2.32.4.2.0')) ne 'UnknownOID'){$host->{MODEL}=$value;$host->{TRACE}.='6-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.253.8.53.3.2.1.2.1')) ne 'UnknownOID'){$host->{MODEL}=$value;$host->{TRACE}.='7-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.236.11.5.1.1.1.0')) ne 'UnknownOID'){$host->{MODEL}=$value;$host->{TRACE}.='8-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.1602.1.1.1.1.0')) ne 'UnknownOID'){$host->{MODEL}=$value;$host->{TRACE}.='9-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.1347.43.5.1.1.1.1')) ne 'UnknownOID'){$host->{MODEL}=$value;$host->{TRACE}.='10-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.367.3.2.1.1.1.1.0')) ne 'UnknownOID'){$host->{MODEL}=$value;$host->{TRACE}.='11-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.367.3.2.1.7.2.2.3.0')) ne 'UnknownOID'){$host->{MODEL}=$value;$host->{TRACE}.='12-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.641.2.1.2.1.2.1')) ne 'UnknownOID'){$host->{MODEL}=$value;$host->{TRACE}.='13-';}

  $host->{FIRMWARE}='U_O';
  if(($value=$self->request('.1.3.6.1.4.1.11.2.3.9.4.2.1.1.3.6.0')) ne 'UnknownOID'){$host->{FIRMWARE}=$value;$host->{TRACE}.='1-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.1248.1.2.2.2.1.1.2.1.3')) ne 'UnknownOID'){$host->{FIRMWARE}=$value;$host->{TRACE}.='2-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.1248.1.2.2.2.1.1.2.1.4')) ne 'UnknownOID'){$host->{FIRMWARE}=$value;$host->{TRACE}.='3-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.1347.43.5.4.1.5.1.1')) ne 'UnknownOID'){$host->{FIRMWARE}=$value;$host->{TRACE}.='4-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.367.3.2.1.6.1.1.4.1')) ne 'UnknownOID'){$host->{FIRMWARE}=$value;$host->{TRACE}.='5-';}
  elsif(($value=$self->request('.1.3.6.1.4.1.641.1.1.1.0')) ne 'UnknownOID'){$host->{FIRMWARE}=$value;$host->{TRACE}.='6-';}

  $host->{DISPLAY1}=$host->{DISPLAY2}=$host->{DISPLAY3}=$host->{DISPLAY4}='';
  if(($value=$self->request('.1.3.6.1.2.1.43.16.5.1.2.1.1')) ne 'UnknownOID'){$host->{DISPLAY1}=$value;}
  elsif(($value=$self->request('.1.3.6.1.2.1.43.16.5.1.2.1.2')) ne 'UnknownOID'){$host->{DISPLAY2}=$value;}
  elsif(($value=$self->request('.1.3.6.1.2.1.43.16.5.1.2.1.3')) ne 'UnknownOID'){$host->{DISPLAY3}=$value;}
  elsif(($value=$self->request('.1.3.6.1.2.1.43.16.5.1.2.1.4')) ne 'UnknownOID'){$host->{DISPLAY4}=$value;}

  $host->{MAC}='U_O';
  if(($value=$self->request('.1.3.6.1.2.1.2.2.1.6.1')) ne 'UnknownOID'){$host->{MAC}=$value;}

  $host->{CD1}=$host->{CD2}=$host->{CD3}=$host->{CD4}=$host->{CD5}=$host->{CD6}=$host->{CD7}=$host->{CD8}='';
  $host->{CD9}=$host->{CD10}=$host->{CD11}='U_O';
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.6.1.1')) ne 'UnknownOID'){$host->{CD1}=$value};
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.6.1.2')) ne 'UnknownOID'){$host->{CD1}=$value};
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.6.1.3')) ne 'UnknownOID'){$host->{CD3}=$value};
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.6.1.4')) ne 'UnknownOID'){$host->{CD4}=$value};
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.6.1.5')) ne 'UnknownOID'){$host->{CD5}=$value};
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.6.1.6')) ne 'UnknownOID'){$host->{CD6}=$value};
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.6.1.7')) ne 'UnknownOID'){$host->{CD7}=$value};
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.6.1.8')) ne 'UnknownOID'){$host->{CD8}=$value};
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.6.1.9')) ne 'UnknownOID'){$host->{CD9}=$value};
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.6.1.10')) ne 'UnknownOID'){$host->{CD10}=$value};
  if(($value=$self->request('.1.3.6.1.2.1.43.11.1.1.6.1.11')) ne 'UnknownOID'){$host->{CD11}=$value};

  $host->{RESPONSE}='&L1='.$host->{SN}.'&L2='.$host->{TOTAL}.'&L3='.$host->{COLOR}.'&L4='.$host->{MC1}.
                    '&L5='.$host->{CC1}.'&L6='.$host->{MC2}.'&L7='.$host->{CC2}.'&L8='.$host->{MC3}.
                    '&L9='.$host->{CC3}.'&L10='.$host->{MC4}.'&L11='.$host->{CC4}.'&L12='.$host->{MC5}.
                    '&L13='.$host->{CC5}.'&L14='.$host->{MC6}.'&L15='.$host->{CC6}.'&L16='.$host->{MC7}.
                    '&L17='.$host->{CC7}.'&L18='.$host->{MODEL}.'&L19='.$self->{target}.'&L20='.$host->{FIRMWARE}.
                    '&L21='.$host->{DISPLAY1}.'&L22='.$host->{DISPLAY2}.'&L23='.$host->{DISPLAY3}.
                    '&L24='.$host->{DISPLAY4}.'&L90='.$host->{TRACE};

  return $host;
}

sub getmodel
{
  my $self=shift;
  my $answer=shift;
  my $host;
  my $i=0;

  $answer=~s/OK:OIDL#//;
  $host->{RESPONSE}='&';
  my @codes=split("#",$answer);
  foreach my $code(@codes)
  {
    $i++;
    $code=~/\!\!/;
    my $counterid=$`;
    my $oid=$';
    $counterid=~s/\AC/L/; # adapt Color to Legal
    $counterid=~s/\AB/L/; # adapt Black to Legal
    $counterid=~s/\AG/L/; # adapt Generic to Legal
    if($oid=~/\AMAC/)
    {
      $oid=~s/\AMAC//;
      $host->{RESPONSE}.=$counterid.'='.$self->request($oid,'mac').'&';
    }
    else{
      $host->{RESPONSE}.=$counterid.'='.$self->request($oid).'&';
    }
  } 
  return $host;
}

1;

__END__

=head1 NAME

CPM - Simple module to work with MyPrinterCloud system

=head1 SYNOPSIS

 use CPM;
 my $env=CPM->new();
 my $oid='.1.3.6.1.2.1.2.2.1.6.2';
 my $result=$env->request($oid, -type=>'mac');
 print "MAC: $result\n";

=head1 DESCRIPTION

The CPM module manages the API of MyPrinterCloud.

=head1 AUTHOR

Juan José 'Peco' San Martín, C<< <peco at cpan.org> >>

=head1 COPYRIGHT

Copyright 2010 Nubeprint

This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=cut

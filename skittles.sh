#!/bin/sh

# The following Skittle Grinder is designed to copy essential system files and obtain
# listings of files, processes, logfiles. The results are collected in one file
# for the purpose of determining if the system was compromised.  This Skittle Grinder
# will cause changes to some file time stamps and will write the results to 
# unallocated clusters unless directed to remote or removable file systems.
# Experience has shown that the evidence obtained from a live system 
# is invaluable for intrusion investigation.
# THIS SCRIPT MUST BE RUN AS ROOT.
#
# 
#
if [ "$(id -u)" != "0" ]; then
    echo "Sorry, you must run this script as root." 1>&2
    exit 1
fi
PATH=/bin:/usr/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin:/etc:/usr/ucb
export PATH
CWD=`pwd`
echo "Current Working Directory is $CWD"
echo
echo "***********************************************************************"
echo
echo " Thank you for choosing Skittle Grinder as your premier log"
echo " collection source! "
echo
echo " This product has been brought you by R@1nb0wD@$h"
echo " and WiredPulse."          
echo
echo " Please read the messages at the end of this script. "
echo
echo "		*Message will scroll in 10 seconds*"
echo
echo "***********************************************************************"
sleep 10 
	echo
	echo "#######################################################################"
	echo 
	echo " The Skittle Grinder Script collects all log files and"
	echo 
	echo " some system files.  If the logfiles are neglected"
	echo 
	echo " they can grow quite large. You are about to see a" 
	echo
	echo " listing of your mounted file systems."
	echo
	echo " PLEASE NOTE THE PARTITION/DIRECTORY WITH THE MOST SPACE"
	echo
	echo "		*Message will scroll in 15 seconds*"
	echo
	echo "#######################################################################"
sleep 15	
# Show disk free space
echo
echo "#######################################################################"
df
echo
echo
echo "		*Message will scroll in 15 seconds*"
echo "#######################################################################"
sleep 15
	echo
	echo "#######################################################################"
	echo 
	echo " You will be asked to enter a directory where you want"
	echo
	echo " Skittle Grinder to collect the files. "
	echo
	echo " For example to place the files in the /usr directory"
	echo
	echo " Type in   /usr   or any directory you choose"
	echo
	echo " FORENSIC NOTE:  This script will write the results to the"
	echo
	echo " mounted file system of your choice.  If you want to keep"
	echo
	echo " changes to the unallocated clusters to a minimum; "
	echo
	echo " direct the output to a nfs file system instead." 	
	echo
	echo
	echo "		*Message will scroll in 15 seconds*"
	echo
	echo "#######################################################################"
sleep 15
echo
echo
SG=
while [ -z "$SG" ] ;
do
	echo "Please type in the full path of the collection directory:"
	echo
	printf "Collection Directory>"
	read SG
	if [ ! -d "$SG" ] ; then
		echo 
		echo " ERROR...THAT IS NOT A DIRECTORY ON YOUR FILE SYSTEM"
		echo 
		echo " Please type in the full path of a directory on your file system "
		SG=
	fi
done

if [ ! -d "$SG/skittles" ] ; then 
	mkdir $SG/skittles
	mkdir $SG/skittles/system
	mkdir $SG/skittles/network
	mkdir $SG/skittles/config
	mkdir $SG/skittles/files
   else echo " ************************************************************"
	echo " A $SG/skittles directory already exists on your system."
        echo " Please move the directory temporarily and rerun the script."
	echo " ************************************************************" 
exit
fi
cd "$SG"/skittles
TDATE=
TTIME=
while [ -z "$TTIME" ];
do
	echo 
	echo
	echo "################################################################"
	echo
	echo "Due to the inaccuracy of the Computer date and time clock we"
	echo "need to have you type in the actual date and time from a source"
	echo "other than the computer (i.e. wrist watch or room clock )"
	echo
	echo "################################################################"
	echo
	echo "****************************************************************"
	echo
	echo > "$SG"/skittles/TDConfirm.txt
	echo "The System Administrator entered the following information:" >> "$SG"/skittles/TDConfirm.txt
	echo >> "$SG"/skittles/TDConfirm.txt
	echo >> "$SG"/skittles/TDConfirm.txt
	printf " PLEASE TYPE IN THE EXACT DATE (MM/DD/YY) > "
	read TDATE
	echo
	printf " THANK YOU, NOW PLEASE TYPE IN THE TIME (HH:MM) > "
	read TTIME
	echo $TDATE >> "$SG"/skittles/TDConfirm.txt
	echo $TTIME >> "$SG"/skittles/TDConfirm.txt
done
		# Obtaining Process List
		#
		echo
		echo "########################"
    		echo "#Grinding Process List #"
    		echo "########################"
		echo
		/bin/ps aux > $SG/skittles/system/psaux.txt
		/bin/ps aux --forest > $SG/skittles/system/psauxf.txt
		if [ -x /usr/bin/pstree ]; then /usr/bin/pstree > $SG/skittles/system/pstree.txt ; fi
		#
		# Looking for SUID files and obtaining list of all files
		# 
		echo
		echo "#########################################################"
		echo "#Grinding for SUID Files and Obtaining List of All Files#"
		echo "#This may take some time if there are a lot of files    #"
		echo "#If this takes longer than 30 minutes, stop the         #"
		echo "#Skittle Grinder using Cntl-C.                          #"
		echo "#########################################################"
		find / -user root -perm +4000 ! -fstype nfs -print > $SG/skittles/files/suid.txt 2>>./SGerr.txt
		printf ">>> Done with Part 1 of 5 "
                find / -user root -perm +2000 ! -fstype nfs -print > $SG/skittles/files/guid.txt 2>>./SGerr.txt
		printf ">>> Done with Part 2 of 5 "
		#Reduced this collection to only the /etc directory
		ls -AlR /etc > $SG/skittles/files/lsAlR-etc.txt 2>>./SGerr.txt
		printf ">>> Done with Part 3 of 5 "
		ls -AlRc --full-time / > $SG/skittles/files/lsAlRc.txt 2>>./SGerr.txt
		printf ">>>Done with Part 4 of 5 "
		for stat in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin
		do
		stat $stat/* >> $SG/skittles/files/statbins.txt
		#New v.4
		find $stat -type f -exec /usr/bin/md5sum {} \; >> $SG/skittles/files/md5check.txt 2>/dev/null
		done
		printf ">>> Done with Part 5 of 5 "
		echo
		
		#
		# Checking for and collecting .rhosts files
		#
		echo
		echo "######################################################"
		echo "#Grinding for contents of .rhosts files              #"
		echo "######################################################"
		echo
		find / -name .rhosts -print > $SG/skittles/config/rhosts.txt 2>/dev/null
		for rh in `cat $SG/skittles/config/rhosts.txt`
		do
		cat $rh >> $SG/skittles/config/rhostcon.txt
		done
		#
		# Obtaining Network and System Information
		#
		echo
		echo "##########################################"
		echo "#Grinding Network and System Information #"
		echo "##########################################"
		echo 
		uname -a > $SG/skittles/uname.txt
		ifconfig -a > $SG/skittles/network/ifconfig.txt
		netstat -a > $SG/skittles/network/netstata.txt
		netstat -an > $SG/skittles/network/netstatan.txt
		netstat -i > $SG/skittles/network/netstati.txt
		rpcinfo -p > $SG/skittles/network/rpcinfo.txt 2>>./SGerr.txt
		iptables -L > $SG/skittles/network/iptables.txt
		ip6tables -L > $SG/skittles/network/ip6tables.txt
		netables -L > $SG/skittles/network/netables.txt
		arptables -L > $SG/skittles/network/arptables.txt
		dmesg > $SG/skittles/system/dmesg.txt
		last > $SG/skittles/system/last.txt
		w > $SG/skittles/system/what.txt
		df -k > $SG/skittles/system/df-k.txt
		df -h > $SG/skittles/system/df-h.txt 2>>$SG/skittles/SGerr.txt
		if [ -x /usr/sbin/lsof ] ; then lsof > $SG/skittles/system/lsof.txt ; fi
		ipcs -a > $SG/skittles/system/ipcs.txt
		echo >> $SG/skittles/TDConfirm.txt
		echo >> $SG/skittles/TDConfirm.txt
		echo "SYSTEM TIME SHOWS THIS INFORMATION:" >> $SG/skittles/TDConfirm.txt
		echo >> $SG/skittles/TDConfirm.txt
		date >> $SG/skittles/TDConfirm.txt
		date -u >> $SG/skittles/TDConfirm.txt
		mount > $SG/skittles/system/mount.txt
		lsmod > $SG/skittles/system/lsmod.txt

		# Copying Specific System Files
		# These files are collected to check for changes or unauthrized
		# entries
		echo
		echo "################################"
		echo "#Grinding Specific System Files#"
		echo "################################"
		echo
		if [ -f /etc/issue ] ; then cat /etc/issue >> $SG/skittles/uname.txt; fi
		if [ -f /etc/inetd.conf ] ; then cp /etc/inetd.conf $SG/skittles/config/ ; fi
		if [ -f /etc/passwd ] ; then cp /etc/passwd $SG/skittles/config/ ; fi
		if [ -f /etc/hosts.equiv ] ; then cp /etc/hosts.equiv $SG/skittles/config/ ; fi
		if [ -f /etc/group ] ; then cp /etc/group $SG/skittles/config/ ; fi
		if [ -f /etc/shadow ] ; then cp /etc/shadow $SG/skittles/config/ ; fi
		if [ -f /etc/hosts ] ; then cp /etc/hosts $SG/skittles/config/ ; fi
		if [ -f /etc/syslog.conf ] ; then cp /etc/syslog.conf $SG/skittles/config/ ; fi
		if [ -f /core ] ; then strings /core > $SG/skittles/system/core.txt ; fi
		# New v. 3
		if [ -f /etc/hosts.allow ] ; then cp /etc/hosts.allow $SG/skittles/config/ ; fi
		if [ -f /etc/hosts.deny ] ; then cp /etc/hosts.deny $SG/skittles/config/ ; fi
		# Checking for xinetd
		if [ -d /etc/xinetd.d ] ; then cp -r /etc/xinetd.d $SG/skittles/config/ ; fi
		if [ -f /etc/xinetd.conf ] ; then cp /etc/xinetd.conf $SG/skittles/config/ ; fi
		# Grab system clock settings
		if [ -f /etc/sysconfig/clock ] ; then cp /etc/sysconfig/clock $SG/skittles/config/ ; fi
		if [ -f /etc/services ] ; then cp -p /etc/services $SG/skittles/config/ ; fi
			
		#
		# Collecting Strings of Binaries.  The output of these file
		# are examined for indication of Rootkit or Trojans
		#
		echo
		echo "#######################################"
		echo "#Grinding Strings Output of Binaries  #"
		echo "#######################################"
		echo
		mkdir $SG/skittles/strngs
		unalias login > /dev/null 2>&1
		unalias ls > /dev/null 2>&1
		unalias netstat > /dev/null 2>&1
		unalias ps > /dev/null 2>&1
		unalias dirname > /dev/null 2>&1
		for BIN in ls find du ps netstat ifconfig crontab syslogd login in.fingerd in.telnetd \
		passwd su strings pstree init amd biff cron basename chfn chsh date dirname echo egrep \
		env find fingerd gpm grep hdparm in.ftpd identd killall ldsopreload lsof mail mingetty \
		named pidof pop2 pop3 rpcinfo rlogind rshd slogin sendmail sshd tar tcpd tcpdump \
		top telnetd timed traceroute vdir w write xinetd automount
		do
		b=`which $BIN 2>/dev/null`
		if [ ! -z "$b" ] && [ -f "$b" ]; then 
		strings -a $b > $SG/skittles/strngs/$BIN.txt 2>>$SG/skittles/SGerr.txt
		fi
		unset b
		done
		for BIN in ls find du ps netstat ifconfig crontab syslogd login in.fingerd in.telnetd \
		passwd su strings pstree init amd biff cron basename chfn chsh date dirname echo egrep \
		env find fingerd gpm grep hdparm in.ftpd identd killall ldsopreload lsof mail mingetty \
		named pidof pop2 pop3 rpcinfo rlogind rshd slogin sendmail sshd tar tcpd tcpdump \
		top telnetd timed traceroute vdir w write xinetd automount
		do
		which $BIN 2>/dev/null >> $SG/skittles/strngs/whichbin.txt
		done
		#
		# Collecting Log Directories and Files
		# These files are examined for indications of
		# intrusion.
		#
		echo
		echo "######################################"
		echo "#Grinding Log Directories and Files  #"
		echo "######################################"
		echo
		logsize=`du -ks /var/log |awk '{ print $1 ; }'`
		# If log file size becomes an issue, change below to 1
		mlz=200000
		if [ "$logsize" -lt "$mlz" ] ; then
			if [ -d /var/log ] ; then cp -rp /var/log ./logfiles ; fi
		else	echo
			echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
			echo "LOG DIRECTORY IS TOO LARGE. "
			echo "Trying Alternate Skittle Grind"
			echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
			mkdir $SG/skittles/logfiles
			if [ -d /var/log ] ; then cp -p /var/log/* ./logfiles ; fi
		fi
		find / -name ".*history" 2>/dev/null | cpio -ocB >$SG/skittles/logfiles/HISTORY-FILES.txt 
last $SG/skittles/logfiles/wtmp > $SG/skittles/logfiles/wtmp.txt
last $SG/skittles/logfiles/btmp > $SG/skittles/logfiles/btmp.txt
rm $SG/skittles/logfiles/wtmp
rm $SG/skittles/logfiles/btmp


# End of System Collection Sections
# New to version 5
# Rootkit Search Module
# This module is brand new.  It conducts a quick set of file tests looking for known
# Rootkits
# Don't rely soley on this report for positive or negative confirmation of an intrusion.

### suspicious files and sniffer's logs
echo
echo "#############################################"
echo "# Grinding Rootkit Search                   #"
echo "#############################################"
echo
##
echo "The following report looks for known suspect files found in the file system." >> $SG/skittles/RKCheck.txt
echo "Confirm the existance of these files in the lsAlRc.out file" >> $SG/skittles/RKCheck.txt 
echo "----------------------------------------------------------------------------" >> $SG/skittles/RKCheck.txt
echo >> $SG/skittles/RKCheck.txt
echo >> $SG/skittles/RKCheck.txt

suspfiles="/usr/lib/pt07 /usr/bin/atm /tmp/.cheese /dev/ptyzx /dev/ptyzy /usr/bin/sourcemask /dev/ida \
/dev/xdf1 /dev/xdf2 /usr/bin/xstat /tmp/982235016-gtkrc-429249277 /usr/bin/sourcemask /usr/bin/ras2xm \
/usr/sbin/in.telnet /sbin/vobiscum /usr/sbin/jcd /usr/sbin/atd2 /usr/bin/.etc /etc/ld.so.hash \
/sbin/init.zk /usr/lib/in.httpd /usr/lib/in.pop3 /usr/bin/ypwatch /dev/hda06 /dev/ptyy /dev/ptyu \
/dev/ptyu /dev/ptyq /dev/ptyv /dev/hdbb /dev/mdev"

for f in ${suspfiles}

do
if [ -f "$f" ] ; then
	echo "Found Suspect file -> $f " >> $SG/skittles/RKCheck.txt 2>/dev/null
	echo >> $SG/skittles/RKCheck.txt
fi
done
suspdir="/var/run/.tmp /lib/.so /usr/lib/.fx /var/local/.lpd /dev/rd/cdb /lib/security/.config \
/usr/info/libc1.so /dev/wd4 /dev/portd /usr/bin/duarawkz"

for d in ${suspdir}
do
if [ -d "$d" ] ; then
	echo "Found Suspect directory -> $d " >> $SG/skittles/RKCheck.txt
	echo >> $SG/skittles/RKCheck.txt
fi
done

#Checking for HiDRootkit
   if [ -d /var/lib/games/.k ] ; then
      echo "Found possible HiDrootkit installed in /var/lib/games/.k" >> $SG/skittles/RKCheck.txt
   fi
#Checking for t0rn RKs
   if [ -f /etc/ttyhash -o -f /sbin/xlogin -o -d /usr/src/.puta -o -r /lib/ldlib.tk -o -d /usr/info/.t0rn ];
   then
      echo "Found possible t0rn rootkit-> Look for ttyhash/xlogin/.puta/ldlib.tk/.torn" >> $SG/skittles/RKCheck.txt
      echo >> $SG/skittles/RKCheck.txt
   fi
   if [ -f /lib/libproc.a -o -f /usr/lib/libproc.a -o -f /usr/local/lib/libproc.a ]; then
      echo "Found possible t0rn v8 rootkit installed-> Look for libproc.a ">> $SG/skittles/RKCheck.txt
      echo >> $SG/skittles/RKCheck.txt
   fi
#Checking for RSHA rootkits
   if [ -r /bin/kr4p -o -r /usr/bin/n3tstat -o -r /usr/bin/chsh2 -o -r /usr/bin/slice2 \
	-o -r /usr/src/linux/arch/alpha/lib/.lib/.1proc -o -r /etc/rc.d/arch/alpha/lib/.lib/.1addr \
	-o -d /etc/rc.d/rsha -o -d /etc/rc.d/arch/alpha/lib/.lib ]; then
      echo "Found possible RSHA rootkit installed-> check for kr4p, n3tstat, chsh2,">>$SG/skittles/RKCheck.txt
      echo "slice2, .1proc, .1addr files or rsha and .lib directories" >>$SG/skittles/RKCheck.txt
      echo >>$SG/skittles/RKCheck.txt
   fi
#Checking for RH-Sharpe Rootkit
   if [ -r /bin/lps -o -r /usr/bin/lpstree -o -r /usr/bin/ltop -o -r /usr/bin/lkillall \
	-o -r /usr/bin/ldu -o -r /usr/bin/lnetstat -o -r /usr/bin/wp -o -r /usr/bin/shad \
	-o -r /usr/bin/vadim -o -r /usr/bin/slice -o -r /usr/bin/cleaner -o -r /usr/include/rpcsvc/du ]; then
     echo "Found possible RH-Sharpe rootkit installed -> check for lps, lpstree,">> $SG/skittles/RKCheck.txt
     echo "ltop, lkillall, ldu, lnetstat, wp, shad, vadim, slice, cleaner /rpcsvc/du" >> $SG/skittles/RKCheck.txt
     echo >> $SG/skittles/RKCheck.txt
   fi
#Checking for ark rootkit.
   if [ -d /dev/ptyxx -o -r /usr/lib/.ark? -o -d /usr/doc/...  ]; then
      echo "Found possible ark rootkit installed -> check for ptyxx, .ark? or ... " >> $SG/skittles/RKCheck.txt
   fi
#Checking for ShitC Worm
   if [ -f /bin/homo -o -f /bin/frgy -o -f /bin/dy -o -d /usr/bin/dir -o -f /usr/sbin/in.slogind ] ;
	then
	echo "Found possible ShitC Worm -> check for frgy, dy, dir or in.slogind" >> $SG/skittles/RKCheck.txt
   fi
#Checking for Omega Worm
   if [ -f /dev/chr -o -d /dev/chr ]; then
      echo "Found possible Omega Worm -> Check for /dev/chr" >> $SG/skittles/RKCheck.txt
   fi
#Checking for China Worm (Sadmind/IIS Worm)
   if [ -f /dev/cuc -o -d /dev/cuc ]; then
      echo "Found possible China Worm -> Check for /dev/cuc" >> $SG/skittles/RKCheck.txt
   fi
#Checking for MonKit
   if [ -f /lib/defs -o -f /usr/lib/libpikapp.a -o -d /lib/defs -o -d /usr/lib/libpikapp.a ]; then
      echo "Found possible Monkit -> Check for defs and libpikapp.a" >> $SG/skittles/RKCheck.txt
   fi
#Checking for X-Org Kit
   if [ -d /usr/lib/libX.a ] ; then
	echo "Found possible X-Org kit -> Check for /usr/lib/libX.a" >> $SG/skittles/RKCheck.txt
   fi
#Check for Romanian Rootkit
      if [ -f /usr/include/file.h -o -f /usr/include/proc.h -o -f /usr/include/addr.h \
-o -f /usr/include/syslogs.h ]; then
	echo "Found possible Romanian Kit->Check for file.h, proc.h, addr.h and syslogs.h" >> $SG/skittles/RKCheck.txt
      fi
#Checking for Showtee
   if [ -d /usr/lib/.egcs ] || [ -f /usr/lib/libfl.so ] || \
      [ -d /usr/lib/.kinetic ] || [ -d /usr/lib/.wormie ] || \
      [ -f /usr/lib/liblog.o ] || [ -f /usr/include/addr.h ] || \
      [ -f /usr/include/cron.h ] || [ -f /usr/include/file.h ] || \
      [ -f /usr/include/proc.h ] || [ -f /usr/include/syslogs.h ] || \
      [ -f /usr/include/chk.h ]; then
      echo "Found possible Showtee Rootkit -> Check for the following:" >> $SG/skittles/RKCheck.txt
      echo ".egcs, libfl.so, .kinetic, .wormie, cron.h, file.h, proc.h, syslogs.h, chk.h" >> $SG/skittles/RKCheck.txt
   fi
#Checking for Optickit
   if [ -f /usr/bin/xchk -o -f /usr/bin/xsf -o -d /usr/bin/xchk -o -d /usr/bin/xsf ]; then
	echo "Found possible Optickit -> Check for xchk or xsf" >> $SG/skittles/RKCheck.txt
   fi
#Checking for Mithra's Rootkit
   if [ -f /usr/lib/locale/uboot -o -d /usr/lib/locale/uboot ]; then
	echo "Found possilbe Mithra RK -> Check for /usr/lib/locale/uboot" >> $SG/skittles/RKCheck.txt
   fi
#Checking for LOC rootkit
   if [ -f /tmp/xp -o -f /tmp/kidd0.c ]; then
	echo "Found possible LOC Rootkit -> Check for /tmp/xp or /tmp/kidd0.c" >> $SG/skittles/RKCheck.txt
   fi
#Checking for AjaKit
   if [ -d /lib/.ligh.gh -o -d /dev/tux ]; then
         echo "Found possible AjaKit rootkit -> Check for /lib/.ligh.gh or /dev/tux " >> $SG/skittles/RKCheck.txt
   fi
#Checking for zaRwT
      if [ -f /bin/imin -o -f /bin/imout ]; then
         echo "Found possible zaRwT rootkit -> Check for /bin/imin or /bin/imout" >> $SG/skittles/RKCheck.txt
      fi
# New to version 5
# Added the ability to execute an auxiliary script
# This will let you add additional file tests and rootkit checks
# without having to change the base script. 
# Insure the auxiliary script is named with SGAx-'date'.sh.
# 
# Let's see if there is an Auxiliary script to execute.
#
if [ -f "$CWD"/SGAx*.sh ] ; then
	echo "Auxiliary Script Found."
	chmod 700 $CWD/SGAx*.sh 
	$CWD/SGAx*.sh $SG 2>>$SG/skittles/SGerr.txt
	echo "Auxiliary Script Completed."
fi
##END OF ROOTKIT MODULE


# Starting Results Grind
if [ ! -d $SG/skittles/logfiles ] ; then
   echo "THIS SYSTEM DOES NOT HAVE STANDARD LOGGING.  LOG DIRECTORY IS MISSING >> $SG/skittles/SGerr.txt
   echo 
   echo "#########################################################"
   echo "#YOUR SYSTEM LOGGING IS NOT A STANDARD CONFIGURATION!   #"
   echo "#Please evaluate your /etc/syslog.conf for the location #"
   echo "#of the directory that contains your log files.         #"
   echo "#Tar the files of that directory and send along with    #"
   echo "#the file created by this script.                       #"
   echo "#########################################################"
   echo
	sleep 5
fi

# Collecting Files
   echo
   echo "#################################################################################"
   echo "#Grinding a tarball of Files from the $SG/skittles Directory                    #"
   echo "#################################################################################"
cd $SG
tar -cf `hostname`.skittles.tar skittles
rm -rf $SG/skittles
type gzip > /dev/null
if [ $? -eq 0 ] ; then gzip `hostname`.skittles.tar
    else compress `hostname`.skittles.tar
fi
md5sum ./`hostname`.skittles.tar.gz > Hash:`hostname` logs
#Closing Messages
echo
echo " ########################################################################"
echo " ALL FILES HAVE BEEN GRINDED!"
echo " There is a new compressed file placed on your system."
if [ -f $SG/`hostname`.skittles.tar.gz ] ; then echo " The file is "`hostname`.skittles.tar.gz "in the $SG directory."
   else echo " The file is "`hostname`.skittles.tar.Z "in the $SG directory."
fi
echo " ENSURE YOU REMOVE THE SKITTLE GRINDER SCRIPT, HASH, AND `hostname`.skittles.tar.(gz or Z)" 
echo " from your system and please, continue to taste the rainbow!"
echo " ########################################################################"
#! /bin/bash

## TODO REALISATION ET VALIDATION / FEDORA, CENTOS, OPENSUSE, DEBIAN pour I+
clear
echo -e "                 #####"
echo -e "                #######"
echo -e "                ##O#O##"
echo -e "                #VVVVV#"
echo -e "              ##  VVV  ##"
echo -e "             #          ##"
echo -e "            #            ##"
echo -e "            #            ###"
echo -e "           QQ#           ##Q"
echo -e "         QQQQQQ#       #QQQQQQ"
echo -e "         QQQQQQQ#     #QQQQQQQ"
echo -e "           QQQQQ#######QQQQQ"
echo -e "\n  SCRIPT AUDIT LINUX - Checks ANSSI v4.1"
#Clement MAILLIOUX - 2020

## VERIFICATION DES COMMANDES EN FONCTION DE LA DISTRIBUTION
## Verifier les conditions d'execution
runconditions=0
echo -e "\n[0] Conditions d'execution"
echo "---------------------------------------"
# verifier qu'on peut ecrire dans /tmp
echo -e "\n[?] Verification des droits d'ecriture dans /tmp..."
echo test > /tmp/audit_test.txt
sleep 1
tmploc=`ls /tmp/audit_test.txt 2>&1`
if [[ $tmploc == "/tmp/audit_test.txt" ]]
then
        echo "[+] Test en ecriture sur /tmp/audit_test.txt OK."
else
        echo "[!] Erreur : Impossible d'ecrire sur /tmp/"
        runconditions=1
fi
rm /tmp/audit_test.txt 2>/dev/null
tmploc=`ls /tmp/audit_test.txt 2>/dev/null`
if [[ $tmploc == "" ]]
then
        echo "[+] Suppression du fichier de test /tmp/audit_test.txt OK."
else
        echo "[!] Erreur : Impossible de supprimer le fichier de test : /tmp/audit_test.txt"
        runconditions=1
fi
# verifier la commande tee
echo -e "\n[?] Verification de la commande pour ecrire les resultats..."
teecom=`find / -name tee 2>/dev/null | grep bin | head -n 1`
if [[ $teecom != "" ]]
then
	echo "[+] Commande OK : $teecom"
else
	echo "[!] Erreur : commande ecriture introuvable."
	runconditions=1
fi
echo -e "\n"
temps=`date`
if [[ $temps != "" ]]
then
	echo "$temps" | $teecom /tmp/0_Audit_Execution.txt
else
	echo "[!00] Erreur : Pas de commande date disponible." | $teecom /tmp/0_Audit_Execution.txt
	runconditions=1
fi
#Verifier execution en root
echo -e "\n[?01] Verification du profil d'execution..."
currentUser=$(whoami)
if [[ $currentUser != "root" ]]
then
        echo "[!01] Erreur : Ce script doit etre execute avec les droits de root. Veuillez recommencer en root ou avec sudo." | $teecom -a /tmp/0_Audit_Execution.txt
	runconditions=1
else
	echo "[+] Profil root OK."
fi
# verifier uname ou equivalent
echo -e "\n[?02] Verification des commandes de base..."
syscom=`find / -name uname 2>/dev/null | grep bin | head -n 1`
if [[ $syscom != "" ]]
then
	echo "[+] Commande d'interrogation systeme OK : $syscom"
else
	echo "[!02] Erreur : commande d'interrogation systeme introuvble." | $teecom -a /tmp/0_Audit_Execution.txt
	runconditions=1
fi
#verifier la version de linux
sysrel=`find / -name lsb_release 2>/dev/null | grep bin | head -n 1`
if [[ $sysrel != "" ]]
then
	echo "[+] Commande OK : $sysrel"
else
	sysrel=`find / -name os-release 2>/dev/null | grep bin | head -n 1`
	if [[ $sysrel != "" ]]
	then
		echo "[+] Fichier OK : $sysrel"
	else
		echo "[i02] Remarque : Pas d'informations trouvees sur la version de linux"
	fi
fi 
# verifier ifconfig ou equivalent
echo -e "\n[?03] Verification des commandes pour interroger les interfaces..."
intcom=`find / -name ifconfig 2>/dev/null | grep bin | head -n 1`
if [[ $intcom != "" ]] 
then
	echo "[+] Commande pour interfaces OK : $intcom"
else
	intcom=`find / -name ip 2>/dev/null | grep bin | head -n 1`
	if [[ $intcom != "" ]]
	then
		echo "[+] Commande pour interfaces OK : $intcom"
	else
		echo "[!03] Erreur : commandes ifconfig et ip introuvables." | $teecom -a /tmp/0_Audit_Execution.txt
		runconditions=1
	fi
fi
# verifier netstat
echo -e "\n[?04] Verification de la commande pour l'ecoute des connexions..."
ecoutecom=`find / -name netstat 2>/dev/null | grep bin | head -n 1`
if [[ $ecoutecom != "" ]]
then
	echo "[+] Commande pour l'ecoute des connexions OK : $ecoutecom"
else
	ecoutecom=`find / -name ss 2>/dev/null | grep bin | head -n 1`
	if [[ $ecoutecom != "" ]]
	then
		echo "[+] Commande pour l'ecoute des connexions OK : $ecoutecom"
	else
		echo "[!04] Erreur : commande d'ecoute des connexions non disponible." | $teecom -a /tmp/0_Audit_Execution.txt
		runconditions=1
	fi
fi
# verifier iptables
echo -e "\n[?05] Verification de la commande de gestion du pare-feu local..."
parefeucom=`find / -name iptables 2>/dev/null | grep bin | head -n 1`
if [[ $parefeucom != "" ]]
then
	echo "[+] Commande pare-feu local OK : $parefeucom"
else
	parefeucom=`find / -name ufw 2>/dev/null | grep bin | head -n 1`
	if [[ $parefeucom != "" ]]
	then
		echo "[+] Commande pare-feu local OK : $parefeucom"
	else
		echo "[!05] Erreur : commande de gestion du pare-feu local introuvable." | $teecom -a /tmp/0_Audit_Execution.txt
		runconditions=1
	fi
fi
# verifier lsblk
echo -e "\n[?06] Verification des commandes pour lister les disques et partitions..."
diskcom=`find / -name lsblk 2>/dev/null | grep bin | head -n 1`
if [[ $diskcom != "" ]]
then
	echo "[+] Commande pour les disques et partitions OK : $diskcom"
else
	echo "[!06] Erreur : Pas de commande pour lister les disques et partitions." | $teecom -a /tmp/0_Audit_Execution.txt
	runconditions=1
fi
# verifier mount
echo -e "\n[?07] Verification des commandes pour lister les points de montages..."
mountcom=`find / -name mount 2>/dev/null | grep bin | head -n 1`
if [[ $mountcom != "" ]]
then
	echo "[+] Commande pour les disques et partitions OK : $mountcom"
else
	echo "[!07] Erreur : Pas de commande pour lister les montages." | $teecom -a /tmp/0_Audit_Execution.txt
	runconditions=1
fi
# verifier ps
echo -e "\n[?08] Verification de la commande d'interrogation des processus..."
processcom=`find / -name ps 2>/dev/null | grep bin | head -n 1`
if [[ $processcom != "" ]]
then
	echo "[+] Commande pour interroger les processus OK : $processcom"
else
	echo "[!08] Erreur : commande pour interroger les processus introuvable." | $teecom -a /tmp/0_Audit_Execution.txt
	runconditions=1
fi
# verifier la commande service
echo -e "\n[?09] Verification des commandes pour interroger les services..."
servcom1=`find / -name service 2>/dev/null | grep bin | head -n 1`
if [[ $servcom1 != "" ]]
then
	echo "[+] Commande pour interroger SysV - OK : $servcom1"
else
	echo "[i09] Remarque : Commande pour interroger SysV introuvable." | $teecom -a /tmp/0_Audit_Execution.txt
fi
servcom2=`find / -name systemctl 2>/dev/null | grep bin | head -n 1`
if [[ $servcom2 != "" ]]
then 
	echo "[+] Commande pour interroger SystemD - OK : $servcom2"
else
	echo "[i09] Remarque : Commande pour interroger SystemD introuvable." | $teecom -a /tmp/0_Audit_Execution.txt
fi
if [[ $servcom1 == "" && $servcom2 == "" ]]
then
	echo "[!09] Erreur : commandes pour interroger les services introuvables." | $teecom -a /tmp/0_Audit_Execution.txt
	runconditions=1
fi
# verifier la presence du fichier de conf sysctl.conf
echo -e "\n[?10] Verification de la presence du fichier sysctl.conf..."
fichsysconf=`find / -name sysctl.conf 2>/dev/null | grep etc | head -n 1`
if [[ $fichsysconf != "" ]]
then
	echo "[+] Chemin vers le fichier $fichsysconf OK"
else
	echo "[i10] Remarque : Pas de fichier sysctl.conf ?" | $teecom -a /tmp/0_Audit_Execution.txt
fi
# verifier la presence du fichier de config de grub 
echo -e "\n[?11] Verification du fichier de configuration de GRUB..."
fichgrub=`find / -name grub.cfg 2>/dev/null | grep boot | head -n 1`
if [[ $fichgrub != "" ]]
then
	echo "[+] Fichier de configuration de grub OK : $fichgrub"
else
	echo "[i11] Absence du fichier de config de GRUB?" | $teecom -a /tmp/0_Audit_Execution.txt
fi
# verification du forcage de l'IOMMU
echo -e "\n[?12] Verification du fichier pour forcer l'IOMMU..."
fichio1=`ls /etc/default/grub`
if [[ $fichio1 != "" ]]
then
	echo "[+] Fichier de config de l'IOMMU OK : $fichio1"
fi
fichio2=`find / -name menu.lst 2>/dev/null | grep grub | head -n 1`
if [[ $fichio2 != "" ]]
then
	echo "[+] Fichier de config de l'iommu OK : $fichio2"
fi
if [[ $fichio1 == "" && $fichio2 == "" ]] 
then
	echo "[!12] Erreur : Pas de fichier detecte pour les parametres du noyau a l'amorcage" | $teecom -a /tmp/0_Audit_Execution.txt
	runconditions=1
fi
# verifier la presence de la commande du statut apparmor
echo -e "\n[?13] Verification de la disponibilite de commande de status de apparmor..."
checkapparmor=`find / -name aa-status 2>/dev/null | grep bin | head -n 1`
if [[ $checkapparmor != "" ]]
then
        echo "[+] Commande $checkapparmor OK"
else
        echo "[i13] Remarque : Apparmor non detecte" | $teecom -a /tmp/0_Audit_Execution.txt
fi
# verifier la presence de la commande du statut de SELinux
echo -e "\n[?14] Verification de la disponibilite de commande de status de SELinux..."
checkselinux=`find / -name sestatus 2>/dev/null | grep bin | head -n 1`
if [[ $checkselinux != "" ]]
then
	echo "[+] Commande SELinux OK: $checkselinux"
else
	echo "[i14] Remarque : SELinux non detecte" | $teecom -a /tmp/0_Audit_Execution.txt
fi
# verifier les commandes dpkg ou equivalent (liste des paquets)
echo -e "\n[?15] Verification des commandes pour interroger les packages..."
packdpkg=`find / -name dpkg 2>/dev/null | grep bin | head -n 1`
if [[ $packdpkg != "" ]]
then
	echo "[+] Commande pour interroger les paquets OK : $packdpkg"
fi
packrpm=`find / -name rpm 2>/dev/null | grep bin | head -n 1`
if [[ $packrpm != "" ]]
then
	echo "[+] Commande pour interroger les paquets OK : $packrpm"
fi
packyum=`find / -name yum 2>/dev/null | grep bin | head -n 1`
if [[ $packyum != "" ]]
then
        echo "[+] Commande pour interroger les paquets OK : $packyum"
fi
if [[ $packdpkg == "" && $packrpm == "" && $packyum == "" ]]
then
	echo "[!15] Erreur : Gestionnaires de paquets (dpkg, yum, rpm) introuvables." | $teecom -a /tmp/0_Audit_Execution.txt
	runconditions=1
fi
# verifier la gestion des depots
echo -e "\n[?16] Verification de la gestion des depots..."
repodnf=`find / -name dnf 2>/dev/null | grep bin | head -n 1`
if [[ $repocdnf != "" ]]
then
	echo "[+] Commande pour lister les depots OK : $repodnf"
fi
repoapt=`ls /etc/apt/sources.list 2>/dev/null`
if [[ $repoapt == "/etc/apt/sources.list" ]]
then
	echo "[+] OK Fichier $repoapt disponible."
fi
repoyum=`find / -name yum 2>/dev/null | grep bin | head -n 1`
if [[ $repoyum != "" ]]
then
	echo "[+] Commande pour lister les depots OK : $repoyum"
fi
repozyp=`find / -name zypper 2>/dev/null | grep bin | head -n 1`
if [[ $repozyp != "" ]]
then
        echo "[+] Commande pour lister les depots OK : $repozyp"
fi
if [[ $repodnf == "" && $repoapt == "" && $repoyum == "" && $repozyp == "" ]]
then
	echo "[!16] Erreur : impossible de trouver comment sont geres les depots" | $teecom -a /tmp/0_Audit_Execution.txt
	runconditions=1
fi
# verifier la commande passwd pour interroger les comptes
echo -e "\n[?17] Verification de la commande pour interroger les comptes du systeme..."
usercom=`find / -name passwd 2>/dev/null | grep bin | head -n 1`
if [[ $usercom != "" ]]
then
	echo "[+] Commande pour lister les comptes OK : $usercom"
else
	echo "[!17] Erreur : impossible de trouver la commande pour les comptes utilisateurs" | $teecom -a /tmp/0_Audit_Execution.txt
	runconditions=1
fi
#verifier le fichier de base de politique des comptes : login.defs
echo -e "\n[?18] Verification du fichier de base de politique des comptes"
userpol=`find / -name login.defs 2>/dev/null | grep etc | head -n 1`
if [[ $userpol != "" ]]
then
	echo "[+] Fichier de base de gestion des comptes OK : $userpol"
else
	echo "[i18] Remarque : Fichier de base de gestion des comptes introuvable." | $teecom -a /tmp/0_Audit_Execution.txt
fi
# verifier le fichier de gestion des passwords pam
echo -e "\n[?19] Verification de la presence du fichier de gestion des passwords (PAM)..."
pamcompass=`find / -name common-password 2>/dev/null | grep etc | head -n 1`
if [[ $pamcompass != "" ]]
then
	echo "[+] Fichier OK : $pamcompass"
else
	echo "[i19] Remarque : pas de fichier common-password detecte" | $teecom -a /tmp/0_Audit_Execution.txt
fi
pampwqual=`find / -name pwquality.conf 2>/dev/null | grep security | head -n 1`
if [[ $pampwqual != "" ]]
then 
	echo "[+] Fichier OK : $pampwqual"
else
	echo "[i19] Remarque : pas de fichier pwquality.conf detecte" | $teecom -a /tmp/0_Audit_Execution.txt 
fi
# verifier la commande pour les taches planifiees
echo -e "\n[?20] Verification des fichiers de taches planifiees..."
fichcron1=`find / -name crontab 2>/dev/null | grep etc | head -n 1`
if [[ $fichcron1 != "" ]]
then
        echo "[+] Chemin vers le fichier de taches planifiees systeme OK : $fichcron1"
else
        echo "[i20] Remarque : Pas de chemin valide vers les taches planifiees..." | $teecom -a /tmp/0_Audit_Execution.txt
fi
fichcron2=`find / -name cron.hourly 2>/dev/null | grep etc | head -n 1`
if [[ fichcron2 != "" ]]
then
	tabcronh=($(find $fichcron2 -type f 2>/dev/null))
	echo "[+] Chemin vers $fichcron2 : OK"
fi
fichcron2=`find / -name cron.daily 2>/dev/null | grep etc | head -n 1`
if [[ $fichcron2 != "" ]]
then
	tabcrond=($(find $fichcron2 -type f 2>/dev/null))
	echo "[+] Chemin vers $fichcron2 : OK"
fi
fichcron2=`find / -name cron.weekly 2>/dev/null | grep etc | head -n 1`
if [[ $fichcron2 != "" ]]
then
	tabcronw=($(find $fichcron2 -type f 2>/dev/null))
	echo "[+] Chemin vers $fichcron2 : OK"
fi
fichcron2=`find / -name cron.monthly 2>/dev/null | grep etc | head -n 1`
if [[ $fichcron2 != "" ]]
then
	tabcronm=($(find $fichcron2 -type f 2>/dev/null))
	echo "[+] Chemin vers $fichcron2 : OK"
fi
fichcron2=`find / -name cron 2>/dev/null | grep spool | head -n 1`
if [[ $fichcron2 != "" ]]
then
	tabcronu=($(find $fichcron2 -type f 2>/dev/null))
	echo "[+] Chemin vers taches des users $fichcron2 : OK"
fi
# verifier la presence de ldd
echo -e "\n[?21] Verification de la commande ldd..."
comldd=`find / -name ldd 2>/dev/null | grep bin | head -n 1`
if [[ $comldd ]]
then
	echo "[+] Commande de check des dependances ok : $comldd"
else
	echo "[!21] Erreur : Pas de commande pour checker les dependances." | $teecom -a /tmp/0_Audit_Execution.txt
	runconditions=1
fi

## SCRIPT DE RECUPERATION DES INFORMATIONS
## Si tout satifait, demarrage du script
if [[ runconditions -eq 0 ]]
then 
	echo -e "\n[I] Informations basiques" | $teecom  /tmp/1_Audit_Basic.txt
	echo '---------------------------------------' | $teecom -a /tmp/1_Audit_Basic.txt
	echo "[*] Date et heure de demarrage" | $teecom -a /tmp/1_Audit_Basic.txt
	date >> /tmp/1_Audit_Basic.txt
	echo -e "\n" >> /tmp/1_Audit_Basic.txt
	echo "[R8/R9] Kernel Version..." | $teecom -a /tmp/1_Audit_Basic.txt
	$syscom -v >> /tmp/1_Audit_Basic.txt 
	if [[ $sysrel =~ .*lsb_release.* ]]
	then
		$sysrel -d >> /tmp/1_Audit_Basic
		echo -e "\n" >> /tmp/1_Audit_Basic
	else
		if [[ $sysrel =~ .*os-release.* ]]
		then
			cat $sysrel
			echo -e "\n" >> /tmp/1_Audit_Basic
		fi
	fi 
	echo "[R10] Kernel Release..." | $teecom -a /tmp/1_Audit_Basic.txt
	$syscom -r >> /tmp/1_Audit_Basic.txt
	echo -e "\n" >> /tmp/1_Audit_Basic.txt
	echo "[*] Hostname..." | $teecom -a /tmp/1_Audit_Basic.txt
	hostname >> /tmp/1_Audit_Basic.txt
	echo -e "\n" >> /tmp/1_Audit_Basic.txt
	echo "[*] Whoami..." | $teecom -a /tmp/1_Audit_Basic.txt
	whoami >> /tmp/1_Audit_Basic.txt
	id >> /tmp/1_Audit_Basic.txt

	echo -e '\n[II] Informations reseau' | $teecom /tmp/2_Audit_Reseau.txt
	echo '---------------------------------------' | $teecom -a /tmp/2_Audit_Reseau.txt
	echo '[R21] Interfaces...' | $teecom -a /tmp/2_Audit_Reseau.txt
	if [[ $intcom =~ .*ifconfig.* ]]
	then
		$intcom -a >> /tmp/2_Audit_Reseau.txt
	else
		$intcom addr >> /tmp/2_Audit_Reseau.txt
	fi
	#check des communications reseau
	echo -e "\n" >> /tmp/2_Audit_Reseau.txt
	echo "[R21/R42] Communications reseau..." | $teecom -a /tmp/2_Audit_Reseau.txt
	if [[ $ecoutecom =~ .*netstat.* ]]
	then
		echo "[+] Commande netstat"
		$ecoutecom -taupe >> /tmp/2_Audit_Reseau.txt
	fi
	if [[ $ecoutecom =~ .*ss.* ]]
	then
		echo "[+] Commande ss"
                $ecoutecom -a >> /tmp/2_Audit_Reseau.txt
	fi 
	#check de la config du pare-feu
	echo -e "\n" >> /tmp/2_Audit_Reseau.txt
	echo "[R21] Pare-feu local (raw)..." | $teecom -a /tmp/2_Audit_Reseau.txt
	$parefeucom -L -t raw >> /tmp/2_Audit_Reseau.txt
	echo -e "\n" >> /tmp/2_Audit_Reseau.txt
	echo -e "[R21] Pare-feu local (mangle)..." | $teecom -a /tmp/2_Audit_Reseau.txt
	$parefeucom -L -t mangle >> /tmp/2_Audit_Reseau.txt
	echo -e "\n" >> /tmp/2_Audit_Reseau.txt
	echo "[R21] Pare-feu local (filter)..." | $teecom -a /tmp/2_Audit_Reseau.txt
	$parefeucom -L -t filter >> /tmp/2_Audit_Reseau.txt
	echo -e "\n" >> /tmp/2_Audit_Reseau.txt
	echo "[R21] Pare-feu local (nat)..." | $teecom -a /tmp/2_Audit_Reseau.txt
	$parefeucom -L -t nat >> /tmp/2_Audit_Reseau.txt

	echo -e "\n[III] Systeme" | $teecom /tmp/3_Audit_Systeme.txt
        echo '---------------------------------------' | $teecom -a /tmp/3_Audit_Systeme.txt
	# check des disques et partitions
	echo "[R12] Liste des disques et partitions..." | $teecom -a /tmp/3_Audit_Systeme.txt
	echo "[+] Liste des disques."
	$diskcom >> /tmp/3_Audit_Systeme.txt
	echo -e "\n" >> /tmp/3_Audit_Systeme.txt
	echo "[+] Liste des points de montage." | $teecom -a  /tmp/3_Audit_Systeme.txt
	$mountcom >> /tmp/3_Audit_Systeme.txt
	# liste des processus en cours
	echo -e "\n" >> /tmp/3_Audit_Systeme.txt
	echo "[R1/R3/R42] Liste des processus..." | $teecom -a /tmp/3_Audit_Systeme.txt
	$processcom -aux >> /tmp/3_Audit_Systeme.txt
	#check des services
	echo -e "\n" >> /tmp/3_Audit_Systeme.txt
	echo "[R1/R2/R42] Liste des services..." | $teecom -a /tmp/3_Audit_Systeme.txt
	if [[ $servcom1 != "" ]]
	then
		echo "[+] Liste des services sysV..." | $teecom -a /tmp/3_Audit_Systeme.txt
		$servcom1 --status-all >> /tmp/3_Audit_Systeme.txt
	fi
	if [[ $servcom2 != "" ]]
	then
		echo -e "\n" >> /tmp/3_Audit_Systeme.txt
		echo "[+] Liste des services systemD..." | $teecom -a /tmp/3_Audit_Systeme.txt
		$servcom2 list-unit-files >> /tmp/3_Audit_Systeme.txt
	fi
	#recuperation du fichier sysctl.conf
	echo -e "\n" >> /tmp/3_Audit_Systeme.txt
	if [[ $fichsysconf != "" ]]
	then
		echo "[R22/R23/R24] Recuperation de $fichsysconf..." | $teecom -a /tmp/3_Audit_Systeme.txt
		cat $fichsysconf >> /tmp/3_Audit_Systeme.txt
	else
		echo "[R22/R23/R24] $fichsysconf non trouve => pas de test." | $teecom -a /tmp/3_Audit_Systeme.txt
	fi
	# check du fichier de config de GRUB2
	if [[ $fichgrub != "" ]]
	then
		echo -e "\n" >> /tmp/3_Audit_Systeme.txt
		echo "[R17] Recuperation du fichier de config de GRUB..." | $teecom -a /tmp/3_Audit_Systeme.txt
		cat $fichgrub >> /tmp/3_Audit_Systeme.txt
	else
		echo -e "\n" >> /tmp/3_Audit_Systeme.txt
		echo "[R17] Pas de traces du fichier de conf de grub => pas de test." | $teecom -a /tmp/3_Audit_Systeme.txt
	fi
	#check des permissions sur /boot
	echo -e "\n" >> /tmp/3_Audit_Systeme.txt
	echo "[R13] Check des permissions sur /boot..." | $teecom -a >> /tmp/3_Audit_Systeme.txt
	ls -lah / | grep boot | head -n 1 >> /tmp/3_Audit_Systeme.txt
	# check de l'iommu
	if [[ $fichio1 != "" ]]
	then
		echo "\n" >> /tmp/3_Audit_Systeme.txt
		echo "[R11] Check de l'IOMMU dans le fichier $fichio1" | $teecom -a /tmp/3_Audit_Systeme.txt
		cat $fichio1 >> /tmp/3_Audit_Systeme.txt
	fi
	if [[ $fichio2 != "" ]]
	then
		echo "\n" >> /tmp/3_Audit_Systeme.txt
		echo "[R11] Check de l'IOMMU dans le fichier $fichio2" | $teecom -a /tmp/3_Audit_Systeme.txt
		cat $fichio2 >> /tmp/3_Audit_Systeme.txt
	fi
	#check de l'activation de Apparmor
	if [[ $checkapparmor != "" ]]
	then
		echo -e "\n" >> /tmp/3_Audit_Systeme.txt
		echo "[R65] Check du status de Apparmor..."  | $teecom -a /tmp/3_Audit_Systeme.txt
		aa-status >> /tmp/3_Audit_Systeme.txt
	fi
        #check de l'activation de SELinux
        if [[ $checkselinux != "" ]]
        then
                echo -e "\n" >> /tmp/3_Audit_Systeme.txt
                echo "[R66] Check du status de SELinux..."  | $teecom -a /tmp/3_Audit_Systeme.txt
                $checkselinux >> /tmp/3_Audit_Systeme.txt
        fi
        #check des taches planifiees
	echo -e "\n" >> /tmp/3_Audit_Systeme.txt
	echo "[*] Liste des taches planifiees..." | $teecom -a /tmp/3_Audit_Systeme.txt
 	echo "[+] Liste des taches systeme..." | $teecom -a /tmp/3_Audit_Systeme.txt
        if [[ $fichcron1 != "" ]]
        then
                cat $fichcron1 >> /tmp/3_Audit_Systeme.txt
                echo -e "\n" >> /tmp/3_Audit_Systeme.txt
        fi
        if [[ ${#tabcronh[@]} -ne 0 ]]
        then
                for fichier in ${tabcronh[@]}
                do
                        echo "[+] Liste des taches de $fichier..." | $teecom -a /tmp/3_Audit_Systeme.txt
                        cat $fichier >> /tmp/3_Audit_Systeme.txt
                        echo "\n" >> /tmp/3_Audit_Systeme.txt
                done 
        fi
        if [[ ${#tabcrond[@]} -ne 0 ]]
        then
                for fichier in ${tabcrond[@]}
                do
                        echo "[+] Liste des taches de $fichier..." | $teecom -a /tmp/3_Audit_Systeme.txt
                        cat $fichier >> /tmp/3_Audit_Systeme.txt
                        echo -e "\n" >> /tmp/3_Audit_Systeme.txt
                done
        fi
	if [[ ${#tabcronw[@]} -ne 0 ]]
        then
                for fichier in ${tabcronw[@]}
                do
                        echo "[+] Liste des taches de $fichier..." | $teecom -a /tmp/3_Audit_Systeme.txt
                        cat $fichier >> /tmp/3_Audit_Systeme.txt
                        echo -e "\n" >> /tmp/3_Audit_Systeme.txt
                done
        fi
	if [[ ${#tabcronm[@]} -ne 0 ]]
        then
                for fichier in ${tabcronm[@]}
                do
                        echo "[+] Liste des taches de $fichier..." | $teecom -a /tmp/3_Audit_Systeme.txt
                        cat $fichier >> /tmp/3_Audit_Systeme.txt
                        echo -e "\n" >> /tmp/3_Audit_Systeme.txt
                done
        fi
	if [[ ${#tabcronu[@]} -ne 0 ]]
        then
                for fichier in ${tabcronu[@]}
                do
                        echo "[+] Liste des taches de $fichier..." | $teecom -a /tmp/3_Audit_Systeme.txt
                        cat $fichier >> /tmp/3_Audit_Systeme.txt
                        echo -e "\n" >> /tmp/3_Audit_Systeme.txt
                done
        fi

        echo -e "\n[IV] Packages et Repositories" | $teecom /tmp/4_Audit_Pkg-Repo.txt
        echo '---------------------------------------' | $teecom -a /tmp/4_Audit_Pkg-Repo.txt
	echo "[R14/R15] Liste des packages..." | $teecom -a /tmp/4_Audit_Pkg-Repo.txt
        if [[ $packdpkg =~ .*dpkg.* ]] 
        then
		echo "[+] Liste des packages de dpkg" | $teecom -a /tmp/4_Audit_Pkg-Repo.txt
                $packdpkg -l >> /tmp/4_Audit_Pkg-Repo.txt
		echo -e "\n" >> /tmp/4_Audit_Pkg-Repo.txt
        fi
	if [[ $packrpm =~ .*rpm.* ]]
	then
		echo "[+] Liste des packages de rpm" | $teecom -a /tmp/4_Audit_Pkg-Repo.txt
		$packrpm -qa >> /tmp/4_Audit_Pkg-Repo.txt
		echo -e "\n" >> /tmp/4_Audit_Pkg-Repo.txt
	fi
	if [[ $packyum =~ .*yum.* ]]
	then
		echo "[+] Liste des packages yum" | $teecom -a /tmp/4_Audit_Pkg-Repo.txt
		$packyum repolist all >> /tmp/4_Audit_Pkg-Repo.txt
		echo -e "\n" >> /tmp/4_Audit_Pkg-Repo.txt
	fi
	echo -e "\n" >> /tmp/4_Audit_Pkg-Repo.txt
	echo "[R16] Liste des depots utilises..." | $teecom -a /tmp/4_Audit_Pkg-Repo.txt
	if [[ $repodnf =~ .*dnf.* ]]
	then
		$repodnf repolist all  >> /tmp/4_Audit_Pkg-Repo.txt
		echo -e "\n" >> /tmp/4_Audit_Pkg-Repo.txt
	fi
	if [[ $repoapt =~ .*sources.list.* ]]
	then
		cat $repoapt >> /tmp/4_Audit_Pkg-Repo.txt
		#Verification des fichiers presents dans /etc/apt/sources.list.d
		array=($(ls $repoapt.d/ 2>/dev/null))
		for fichier in ${array[@]}
		do
			echo -e "\n" >> /tmp/4_Audit_Pkg-Repo.txt
			echo "[+] Fichier custom : $fichier" | $teecom -a /tmp/4_Audit_Pkg-Repo.txt
			cat $repoapt.d/$fichier >> /tmp/4_Audit_Pkg-Repo.txt
			echo -e "\n" >> /tmp/4_Audit_Pkg-Repo.txt
		done
	fi
	if [[ $repoyum =~ .*yum.* ]]
	then
		echo "[+] Liste des depots geres par yum" | $teecom -a /tmp/4_Audit_Pkg-Repo.txt
		$repoyum repolist >> /tmp/4_Audit_Pkg-Repo.txt
		echo -e "\n" >> /tmp/4_Audit_Pkg-Repo.txt
	fi
	if [[ $repozyp =~ .*zypper.* ]]
	then
		echo "[+] Liste des depots geres par zypper" | $teecom -a /tmp/4_Audit_Pkg-Repo.txt
		$repozyp lr >> /tmp/4_Audit_Pkg-Repo.txt
		eco -e "\n" >> /tmp/4_Audit_Pkg-Repo.txt
	fi
	#check des utilisateurs
	echo -e "\n[V] Utilisateurs et acces" | $teecom /tmp/5_Audit_Utilisateurs.txt
	echo '---------------------------------------' | $teecom -a /tmp/5_Audit_Utilisateurs.txt
	echo "[R28] Liste des utilisateurs" | $teecom -a /tmp/5_Audit_Utilisateurs.txt
	cat /etc/passwd >> /tmp/5_Audit_Utilisateurs.txt
	echo -e "\n" >> /tmp/5_Audit_Utilisateurs.txt
	echo "[R27/R26] Statut des utilisateurs et mots de passe..." | $teecom -a /tmp/5_Audit_Utilisateurs.txt #ne marche pas sur centOS
	for user in $(cat /etc/passwd | grep -v shutdown | grep -v nologin | grep -v sync | grep -v false | grep -v halt | cut -d : -f 1)
	do
		$usercom -S $user >> /tmp/5_Audit_Utilisateurs.txt
	done
	#$usercom -S --all >> /tmp/5_Audit_Utilisateurs.txt
	echo -e "\n" >> /tmp/5_Audit_Utilisateurs.txt
	if [[ $userpol != "" ]]
	then
		echo -e "\n" >> /tmp/5_Audit_Utilisateurs.txt
		echo "[R32] Politique de gestion des comptes de base (login.def)" | $teecom -a /tmp/5_Audit_Utilisateurs.txt
		cat $userpol >> /tmp/5_Audit_Utilisateurs.txt
	fi
	if [[ $pamcompass != "" ]]
	then
		echo -e "\n" >> /tmp/5_Audit_Utilisateurs.txt
		echo "[R32] Configuration de $pamcompass" | $teecom -a /tmp/5_Audit_Utilisateurs.txt
		cat $pamcompass >> /tmp/5_Audit_Utilisateurs.txt
	fi
	if [[ $pampwqual != "" ]]
	then
		echo -e "\n" >> /tmp/5_Audit_Utilisateurs.txt
		echo "[R32] Configuration de $pampwqual" | $teecom -a /tmp/5_Audit_Utilisateurs.txt
		cat $pampwqual >> /tmp/5_Audit_Utilisateurs.txt
	fi 
	echo -e "\n" >> /tmp/5_Audit_Utilisateurs.txt
	echo "[R57] Liste des groupes" | $teecom -a /tmp/5_Audit_Utilisateurs.txt
	cat /etc/group >> /tmp/5_Audit_Utilisateurs.txt
	echo -e "\n" >> /tmp/5_Audit_Utilisateurs.txt
	echo "[R57/R58/R59] Liste des sudoers" | $teecom -a /tmp/5_Audit_Utilisateurs.txt
	cat /etc/sudoers >> /tmp/5_Audit_Utilisateurs.txt
	#verifications des fichiers custom de sudoers.d
	array=($(ls /etc/sudoers.d/ 2>/dev/null))
	for fichier in ${array[@]}
	do
		if [[ $fichier != "README" ]]
		then
			echo -e "\n" >> /tmp/5_Audit_Utilisateurs.txt
			echo "[+] Fichier custom dans sudoers.d : $fichier !" | $teecom -a /tmp/5_Audit_Utilisateurs.txt
			cat /etc/sudoers.d/$fichier >> /tmp/5_Audit_Utilisateurs.txt
		fi
	done
        #check du umask des users
        echo -e "\n" >> /tmp/5_Audit_Utilisateurs.txt
		echo "[R35] Check des masques utilisateurs (umask)..." | $teecom -a /tmp/5_Audit_Utilisateurs.txt
        for user in $(cat /etc/passwd | grep -v shutdown | grep -v nologin | grep -v sync | grep -v false | grep -v halt | cut -d : -f 1)
        do
                echo $user >> /tmp/5_Audit_Utilisateurs.txt
                su -l $user -c 'umask' >> /tmp/5_Audit_Utilisateurs.txt
        done

	#Checks des fichiers et des permissions
	echo -e "\n[VI] Fichiers, permissions SETUID/SETGID" | $teecom -a /tmp/6_Audit_Fichiers-Perms.txt
	echo '---------------------------------------' | $teecom -a /tmp/6_Audit_Fichiers-Perms.txt
	echo "[R37/R38] liste des fichiers SETUID/SETGID..." | $teecom -a /tmp/6_Audit_Fichiers-Perms.txt
	find / -type f -perm /6000 -ls 2>/dev/null >> /tmp/6_Audit_Fichiers-Perms.txt
	echo -e "\n" >> /tmp/6_Audit_Fichiers-Perms.txt
	echo "[R36] Fichiers sans utilisateurs ou groupes proprietaires..." | $teecom -a /tmp/6_Audit_Fichiers-Perms.txt
	find / -type f \( -nouser -o -nogroup \) -ls 2>/dev/null >> /tmp/6_Audit_Fichiers-Perms.txt
	echo -e "\n" >> /tmp/6_Audit_Fichiers-Perms.txt
        echo "[R36] Liste des dossiers modifiables par tous sans sticky bit..."  | $teecom -a /tmp/6_Audit_Fichiers-Perms.txt
        find / -type d \( -perm -0002 -a \! -perm -1000 \) -ls 2>/dev/null
	echo -e "\n" >> /tmp/6_Audit_Fichiers-Perms.txt
        echo "[R36] Liste des dossiers modifiables par tous"  | $teecom -a /tmp/6_Audit_Fichiers-Perms.txt
        find / -type d -perm -0002 -ls 2>/dev/null
	echo -e "\n" >> /tmp/6_Audit_Fichiers-Perms.txt
	echo "[R36] Liste des fichiers modifiables par tous..."  | $teecom -a /tmp/6_Audit_Fichiers-Perms.txt
	find / -type f -perm -0002 -ls 2>/dev/null
	echo -e "\n" >> /tmp/6_Audit_Fichiers-Perms.txt

	#Checks lies a l'utilisation de PAM
	echo -e "\n[VII] Utilisation de PAM" | $teecom /tmp/7_Audit_PAM.txt
	echo '---------------------------------------' | $teecom -a /tmp/7_Audit_PAM.txt
	echo "[R30] Recherche des applications utilisant PAM" | $teecom -a /tmp/7_Audit_PAM.txt
	echo "[+] Liste du contenu de /etc/pam.d/" | $teecom -a /tmp/7_Audit_PAM.txt
	fichpamd=($(find /etc/pam.d/ -type f 2>/dev/null))
	for fichier in ${fichpamd[@]}
	do
		if [[ $fichier != "" ]]
		then
			echo -e "\n" >> /tmp/7_Audit_PAM.txt
			echo "[+] Contenu de : $fichier" | $teecom -a /tmp/7_Audit_PAM.txt
			cat $fichier >> /tmp/7_Audit_PAM.txt
		fi
	done
	executablepam=($(for item in $(find /etc/pam.d/ -type f 2>/dev/null | cut -d / -f 4) ; do which $item 2>/dev/null ; done))
	for eachpam in ${executablepam[@]}
	do
		if [[ $eachpam != "" ]]
		then
			echo -e "\n" >> /tmp/7_Audit_PAM.txt
			echo "[+] Verification de la libpam dans $eachpam" | $teecom -a /tmp/7_Audit_PAM.txt
			ldd $eachpam | grep pam >> /tmp/7_Audit_PAM.txt
		fi
	done


	echo -e "\n\n[+] Termine avec succes! Merci de verifier la presence des fichiers \"Audit\" 0 a 7 dans /tmp/ ."
else
	echo -e "\n\n[!] Des erreurs semblent empecher l'execution du script. Un fichier d'erreur est disponible normalement disponible : /tmp/0_Audit_Execution.txt"
fi

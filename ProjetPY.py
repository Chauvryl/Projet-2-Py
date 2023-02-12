# Import des modules nécéssaires pour le script.
import sys, os
import dns.resolver # Importe le module dns.resolver pour envoyer des requêtes DNS
import socket # Importe le module socket pour effectuer des connexions réseau
import requests # Importe le module requests pour effectuer des requêtes HTTP
import json # Importe le module json pour travailler avec des données en format JSON
import csv,datetime,shutil,re, shodan
from prettytable import PrettyTable



# Main definition - constants
menu_actions  = {}  

# =======================
#     MENUS FUNCTIONS
# =======================

# Main menu
def main_menu():
    # os.system('clear')
    os.system('cls')
    
    print("Bienvenue, sur le projet OSINT\nAUTHEUR DU PROJET : ROUABAH Mohamed-Amine ; AYUB TAHIR Anthony ; CHAUVRY Lucas\nRéalisation du projet en 2023\nN'oublier pas de lire le README.TXT pour installer les dépendances.\n")
    print("Choisir une action:")
    print("1. Dnsscan")
    print("2. Shodan")
    print("3. TheHarverster")
    print("4. URLscan.io")
    print("\n0. Quit")
    choice =  input(" >>  ")
    exec_menu(choice)

    return

# Execute menu
def exec_menu(choice):
    os.system('cls')
    ch = choice.lower()
    if ch == '':
        menu_actions['main_menu']()
    else:
        try:
            menu_actions[ch]()
        except KeyError:
            print("Invalid selection, please try again.\n")
            menu_actions['main_menu']()
    return


# Menu 1
def dnsscan_menu():
    os.system('cls')
    # Boucle infinie pour permettre à l'utilisateur de choisir plusieurs options
    while True:
        # Affiche le menu d'options
        print("DNS Scanner")
        print("1. Scanner un domaine")
        print("2. Reverse DNS Lookup")
        print("3. Vérifier si un domaine est malveillant")
        print("4. Retour")
        # Demande à l'utilisateur de choisir une option
        choice = input("Entrer votre choix (1-4): ")
        os.system('cls')

        # Exécute l'option choisie par l'utilisateur
        if choice == '1':
            domain = input("Entrer un nom de domaine: ")
            dns_scan(domain)
        elif choice == '2':
            ip = input("Entrer une adresse IP: ")
            reverse_dns_lookup(ip)
        elif choice == '3':
            domain = input("Entrer un nom de domaine: ")
            check_malicious_domain(domain)
        elif choice == '4':
            # Quitte le programme si l'utilisateur choisit l'option 4
             menu_actions['main_menu']()
             os.system('cls')
        else:

            # Affiche un message pour demander à l'utilisateur de réessayer s'il n'a pas choisi une option valide
            print("Veuillez réessayer.\n")

    # Exécute la fonction principale
    dnsscan_menu()


#Script DNS SCAN
def dns_scan(domain):
    # Essaie de trouver les adresses IP associées à un nom de domaine
    try:
        # Utilise dns.resolver pour obtenir les réponses DNS A (adresses IP) pour le domaine
        answers = dns.resolver.query(domain, 'A')
        # Vérifie si le répertoire pour le domaine n'existe pas et le crée si nécessaire
        if not os.path.exists(domain):
            os.makedirs(domain)
        # Ouvre un fichier pour enregistrer les résultats et écrit les adresses IP associées au domaine
        with open(f'{domain}/resultat.txt', 'w') as file:
            file.write(f'Domaine: {domain}\n')
            for rdata in answers:
                file.write(f'Adresse IP : {rdata.address}\n')
        # Affiche un message indiquant que les résultats ont été enregistrés dans un fichier
        print(f"\nLe resultat pour {domain} a été sauvegardé dans {domain}/resultat.txt.")
    except dns.resolver.NXDOMAIN:
        # Affiche un message si le nom de domaine n'existe pas
        print("\nLe domaine n'existe pas.")
    except dns.resolver.NoAnswer:
        # Affiche un message si aucune adresse IP n'a été trouvée pour le domaine
        print("\nAucune adresse IP n'a été trouvé pour ce domaine.")
    except dns.resolver.NoNameservers:
        # Affiche un message si le serveur DNS n'est pas accessible
        print("\nImpossible d'accéder au serveur DNS.")
    except:
        # Affiche un message générique en cas d'erreur
        print("\nUne erreur s'est produite.")

def reverse_dns_lookup(ip):
    # Essaie de trouver le nom de domaine associé à une adresse IP
    try:
        # Utilise socket.gethostbyaddr pour trouver le nom de domaine associé à l'adresse IP
        domain = socket.gethostbyaddr(ip)
        # Affiche le nom de domaine associé à l'adresse IP
        print(f"\nLe domaine de cette adresse IP {ip} est {domain[0]}")
    except socket.herror:
            # Affiche un message si aucun domaine n'a été trouvé pour l'adresse IP
        print("\nAucun domaine n'a été trouvé pour cette adresse IP.")

def check_malicious_domain(domain):
    # Définit l'URL de l'API de VirusTotal pour la vérification de site Web
    api_url = f"https://www.virustotal.com/vtapi/v2/url/report"

    # Définit la clé API de VirusTotal
    api_key = "f8415566043375c136132d23deab4ead4dc51884403639cfe4392270823cdf85"

    # Construit les paramètres de la requête à l'API
    params = {
        "apikey": api_key,
        "resource": domain
    }

    # Essaie de vérifier si un nom de domaine est malveillant
    try:
        # Effectue une requête à l'API de VirusTotal pour vérifier la sécurité du site Web
        response = requests.get(api_url, params=params)
        # Charge les données de la réponse en format JSON
        data = response.json()

        # Vérifie la réponse de l'API pour déterminer si le site Web est considéré comme malveillant
        if data["positives"] > 0:
            print(f"\nLe site web {domain} est considéré comme malveillant.")
        else:
            print(f"\nLe site web {domain} est considéré comme sécurisé.")
    except:
        # Affiche un message générique en cas d'erreur lors de la vérification du site Web
        print("\nUne erreur s'est produite lors de la vérification du site web.")


# Menu 2
    
# # Créer une instance de la classe API de Shodan
api = shodan.Shodan("7NiDoaY2dVv3RmdzDiXpD4XAsG73c3Lu")
def menu_shodan():
    print("Bienvenue sur le menu Shodan \n")
    print("1. Rechercher des informations sur un hôte")
    print("2. Rechercher des informations sur une adresse IP")
    print("3. Retour")
    option = int(input("Choisissez une option (1-3) : "))

    if option == 1:
        host_search(api)
    elif option == 2:
        ip_search(api)
    elif option == 3: 
        # Quitte le programme si l'utilisateur choisit l'option 4
        menu_actions['main_menu']()
        os.system('cls')
    else:
        print("Erreur dans la saisie du menu")
    
    return
    


# Effectuer une recherche d'hôte en utilisant la méthode host
def host_search(api):
    host = input("Entrez l'adresse IP ou le nom d'hôte à rechercher : ")
    try:
        host_ip = socket.gethostbyname(host)
        resultat = api.host(host_ip)
        print("Informations sur l'hôte :")
        print("IP : ", resultat['ip_str'])
        print("Organisation : ", resultat.get('org', 'N/A'))
        print("OS : ", resultat.get('os', 'N/A'))
        for service in resultat['data']:
            print("Port : ", service['port'])
            print("Service : ", service.get('name', 'N/A'))
            print("Etat : ", service.get('state', 'N/A'))
            print("")
    except Exception as e:
        print("Une erreur s'est produite : ", e)


    print("9. Back")
    print("0. Quit")
    choice = input(" >>  ")
    exec_menu(choice)
    return
        

# Effectuer une recherche d'adresse IP en utilisant la méthode search
def ip_search(api):
    adresse_ip = input("Entrez l'adresse IP à rechercher : ")
    resultats = api.search(adresse_ip)
    if resultats.get('matches'):
        table = PrettyTable(["IP", "Organisation", "OS", "Port", "Service", "Etat"])
        table.max_width["Service"] = 50
        print("Informations sur l'adresse IP :")
        print("Nombre de résultats trouvés : ", resultats['total'])
        nombre_resultats = int(input("Combien de résultats souhaitez-vous afficher? "))
        for i, resultat in enumerate(resultats['matches']):
            if i >= nombre_resultats:
                break
            if resultat.get('data'):
                for service in resultat['data']:
                    if type(service) == dict:
                        table.add_row([resultat['ip_str'], resultat.get('org', 'N/A'), resultat.get('os', 'N/A'),
                                       service['port'], service.get('name', 'N/A'), service.get('state', 'N/A')])
                    else:
                        table.add_row([resultat['ip_str'], resultat.get('org', 'N/A'), resultat.get('os', 'N/A'),
                                       "N/A", service, "N/A"])
            else:
                table.add_row([resultat['ip_str'], resultat.get('org', 'N/A'), resultat.get('os', 'N/A'),
                               "N/A", "N/A", "N/A"])
        print(table)
    else:
        print("Aucun résultat trouvé.")

    print("9. Back")
    print("0. Quit")
    choice = input(" >>  ")
    exec_menu(choice)
    return


# Menu 3
def theHarverster():

    print("Menu TheHarverster !\n")

    # Ici on stock une variable pour revenir dans le répertoire d'origine
    owd = os.getcwd()
    now = datetime.datetime.now()
    name = "\CVE"+"_"+str(now.strftime("%Y-%d-%m_%H-%M-%S-%f"))+".csv"


    domaine = input("Merci de renseigner le domaine ciblé : ")
    limite = input("\nMerci de renseigné une limite de résultat à afficher : ")
    source = input("\nMerci de renseigner une source (all par défaut si rien renseigné mais prend du temps et beaucoup de données) : ")

    if source == "":

        nameFile = input("\nMerci de renseigner le nom du fichier pour l'enregistrement : ")
        regex = re.compile(r'^[a-zA-Z0-9._-]+$')

        while not regex.match(nameFile):

            print("Invalid filename")
            nameFile = input("Merci de renseigner le nom du fichier pour l'enregistrement : ")

        try:

            nameFile = nameFile + "_" +  str(now.strftime("%Y-%d-%m_%H-%M-%S-%f"))
            destination = owd+"\\SaveTH\\"+nameFile+".json"
            cmd = "python3 theHarvester.py -d "+ domaine +" -l "+ limite +" -b all -f "+nameFile+".json"
            fichierH = "theHarvester-master"

            os.chdir(fichierH)
            output = os.popen(cmd).read()
            owd2 = os.getcwd()


            source=owd2+"\\"+nameFile+".json"

            shutil.move(source,destination)
            os.system('cls')

            print("\n La commande c'est déroulé avec succès !!!\n")

        except:

            print("\nune erreur est survenue lors de la commande, merci de ressayer. \nL'erreur provient peut être du domaine saisie ou de la source.")

    else:

        nameFile = input("\nMerci de renseigner le nom du fichier pour l'enregistrement : ")
        regex = re.compile(r'^[a-zA-Z0-9._-]+$')

        while not regex.match(nameFile):

            print("Invalid filename")
            nameFile = input("Merci de renseigner le nom du fichier pour l'enregistrement : ")

        try:
            
            nameFile = nameFile + "_" +  str(now.strftime("%Y-%d-%m_%H-%M-%S-%f"))
            # destination = input("\nOù souhaitez vous enregistrer le résultat (renseigné le chemin d'accès en doublant les \\) : ")+"\\"+nameFile+".json"
            destination = owd+"\\SaveTH\\"+nameFile+".json"
            # print(destination)
            cmd = "python3 theHarvester.py -d "+ domaine +" -l "+ limite +" -b " + source + " -f "+nameFile+".json"
            fichierH = "theHarvester-master"

            os.chdir(fichierH)
            output = os.popen(cmd).read()
            owd2 = os.getcwd()

            # On déplace l'enregistrement du résultat
            source=owd2+"\\"+nameFile+".json"
            # print(source)

            shutil.move(source,destination)
            os.system('cls')

            print("\n La commande c'est déroulé avec succès !!!\n")

        except:

            print("\nune erreur est survenue lors de la commande, merci de ressayer. \nL'erreur provient peut être du domaine saisie ou de la source.\n")

    # print(output)

    os.chdir(owd)


    print("9. Back")
    print("0. Quit")
    choice = input(" >>  ")
    exec_menu(choice)
    return

# Menu 4
def urlscan():
    print("Menu URLSCAN !\n")
    
    # ---------------------------------------------------------------

    while (True):
        apikey = input("\n Inserer votre clef api :")
        url = input("\n Inserer l'url à scan : ")

        try:
            headers = {'API-Key':apikey,'Content-Type':'application/json'}
            data = {"url": url, "visibility": "public"}
            response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))

            if(response.status_code != 200):
                print("code erreur", response.status_code)
                raise Exception

            # print(response)
            # print(type(response))
            break

        except:
            print("Cette clef ne marche pas \n")

    # RESULT
    print(response.json()["result"])


    # ------------------------------------------------------------

    print("9. Back")
    print("0. Quit")
    choice = input(" >>  ")
    exec_menu(choice)
    return

# Back to main menu
def back():
    menu_actions['main_menu']()

# Exit program
def exit():
    sys.exit()

# =======================
#    MENUS DEFINITIONS
# =======================

# Menu definition
menu_actions = {
    'main_menu': main_menu,
    '1': dnsscan_menu,
    '2': menu_shodan,
    '3': theHarverster,
    '4': urlscan,
    '9': back,
    '0': exit,
}

# =======================
#      MAIN PROGRAM
# =======================

# Main Program
if __name__ == "__main__":
    # Launch main menu
    main_menu()
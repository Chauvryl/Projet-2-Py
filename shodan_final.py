import shodan
import socket
from prettytable import PrettyTable



# Créer une instance de la classe API de Shodan
api = shodan.Shodan("7NiDoaY2dVv3RmdzDiXpD4XAsG73c3Lu")

# Définir les différentes options du menu
def menu():
    print("Bienvenue sur le menu Shodan \n")
    print("1. Rechercher des informations sur un hôte")
    print("2. Rechercher des informations sur une adresse IP")
    print("3. Retour")
    option = int(input("Choisissez une option (1-3) : "))
    return option


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







# Boucle pour afficher le menu et effectuer des recherches en fonction de l'option choisie
while True:
    option = menu()
    if option == 1:
        host_search(api)
    elif option == 2:
        ip_search(api)
    else:
        break


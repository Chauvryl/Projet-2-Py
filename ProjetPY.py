# Import the modules needed to run the script.
import sys, os,requests, csv,datetime,shutil,re



# Main definition - constants
menu_actions  = {}  

# =======================
#     MENUS FUNCTIONS
# =======================

# Main menu
def main_menu():
    # os.system('clear')
    
    print("Bienvenu,\n")
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
def dnsscan():
    print("Menu DNSSCAN !\n")
    print("9. Back")
    print("0. Quit")
    choice = input(" >>  ")
    exec_menu(choice)
    return


# Menu 2
def shodan():
    print("Menu SHODAN !\n")
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
            destination = input("\nOù souhaitez vous enregistrer le résultat (renseigné le chemin d'accès en doublant les \\) : ")+"\\"+nameFile+".json"
            cmd = "python3 theHarvester.py -d "+ domaine +" -l "+ limite +" -b all -f "+nameFile+".json"
            fichierH = "theHarvester-master"

            # cmd="python3 theHarvester.py -d qub.ac.uk -l 200 -b duckduckgo -f "+ nameFile +".json"
            os.chdir(fichierH)
            output = os.popen(cmd).read()


            #-------------------------------------------------------------------------------------#
            #------------MODIFIER LE CHEMIN SOURCE DU FICHIER-------------------------------------#
            #-------------------------------------------------------------------------------------#
            source="C:\\Users\\lucas\\Desktop\\Projet-2-Py\\theHarvester-master\\"+nameFile+".json"

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
            destination = input("\nOù souhaitez vous enregistrer le résultat (renseigné le chemin d'accès en doublant les \\) : ")+"\\"+nameFile+".json"

            cmd = "python3 theHarvester.py -d "+ domaine +" -l "+ limite +" -b " + source + " -f "+nameFile+".json"
            fichierH = "theHarvester-master"

            # cmd="python3 theHarvester.py -d qub.ac.uk -l 200 -b duckduckgo -f "+ nameFile +".json"
            os.chdir(fichierH)
            output = os.popen(cmd).read()

            # On déplace l'enregistrement du résultat

            #-------------------------------------------------------------------------------------#
            #------------MODIFIER LE CHEMIN SOURCE DU FICHIER-------------------------------------#
            #-------------------------------------------------------------------------------------#
            source="C:\\Users\\lucas\\Desktop\\Projet-2-Py\\theHarvester-master\\"+nameFile+".json"

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
    '1': dnsscan,
    '2': shodan,
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
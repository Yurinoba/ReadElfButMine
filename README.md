# ReadElfButMine

Un week-end j'ai voulu creuser la structure ELF du coup j'ai créé ça et je me suis dis que ça pouvait être un bon support d'apprentissage pour ceux qui ne 
veulent pas lire la doc mais plutôt rentrer dans la structure avec du code directement.

Petit projet perso pour comprendre un peu mieux la structure ELF et notamment les headers.
Attention l'outil est HYPER verbeux, il sert surtout de support pour aborder la structure ELF sans se reposer uniquement sur la doc.

Si vous voulez plus d'infos sur certains paramètre n'hésitez pas à checker le code, j'ai fais le plus simple/clair possible avec des commentaires
sur des paramètres un peu obscures. 

Si vous voulez plus d'infos n'hésitez pas à creuser la documentation en annexe/upgrade l'outil. 

J'ai pas affiché toutes les infos que readelf renvoie, mais je pense avoir les principales outputs.

Cet outil est aussi pratique comme base pour aller faire des choses plus intéressantes dans l'analyse de binaire ELF, je publierai peut-être un autre projet en public en lien avec ça.

Requirements : 

- 64 bits exec. 32 might be implemented later 

How to use : 

```bash 
gcc readelfbutmine.c -o readelfbutmine
./readelfbutmine <filename> 
```

If you wanna try right now : 
```bash 
./readelfbutmine examples/test
```
I suggest you to read the ELF Header (at the top of the output), one Program Header and one Section Header. It is quite interesting.

How to compare (just trust my output don't worry...) : 

```bash 
readelf -a <filename> 
```

Je ne sais pas si ça marche pour tous les exec 64 bits mais l'objectif est surtout de s'amuser tout en apprennant de nouvelles choses :)

Ressources : 

- File for elf header structure  for me : /usr/include/elf.h
- page wikipedia : https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
- More EFL info : https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-43405/index.html
- ELF header video : https://www.youtube.com/watch?v=5MJW71jftQU
- ProgramHeader : https://www.sco.com/developers/gabi/2000-07-17/ch5.pheader.html
- SectionHeader : https://www.sco.com/developers/gabi/2000-07-17/ch4.sheader.html

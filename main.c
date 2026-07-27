#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <winnt.h>

#define MAX_FILES 100
#define BYTES_PER_LINE 16
#define MAX_SECTIONS 96

int ListFiles(char files[][MAX_PATH]);
int ChooseFile(int count);
void PrintFileInfo(const char *filename);
HANDLE OpenBinaryFile(const char *filename);
void HexDump(HANDLE hFile);
BOOL JumpToOffset(HANDLE hFile);
void DetectFileType(HANDLE hFile);
void ParseDOSHeader(HANDLE hFile);
void ParsePEHeader(HANDLE hFile);
DWORD RvaToFileOffset(DWORD rva, IMAGE_SECTION_HEADER sections[], WORD numberOfSections);
void ShowMenu(void);

int ListFiles(char files[][MAX_PATH]) 
{
WIN32_FIND_DATA fd;
HANDLE hFind;

hFind = FindFirstFile("*", &fd);

if(hFind == INVALID_HANDLE_VALUE){
    printf("Couldn't open the directory.\n");
    return -1;
}


int count = 0;

do{
    if(!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)){
        if (count >= MAX_FILES)
            break;
        strcpy(files[count], fd.cFileName);
        printf("%d. %s\n", count, fd.cFileName);
        count++;
    }
} while(FindNextFile(hFind, &fd));
FindClose(hFind); 
return count;
}


int ChooseFile(int count){
    int choice;

while (1)
{
    printf("Choose a file: ");
    scanf("%d", &choice);

    if (choice >= 0 && choice < count)
        return choice;

    printf("Invalid choice.\n");
}
}


void PrintFileInfo(const char *filename){
    WIN32_FILE_ATTRIBUTE_DATA data;

if (GetFileAttributesEx(filename,
                        GetFileExInfoStandard,
                        &data))
{
    LARGE_INTEGER size;
    size.LowPart = data.nFileSizeLow;
    size.HighPart = data.nFileSizeHigh;

    printf("Size: %lld bytes\n", size.QuadPart);
}
else
{
    printf("Couldn't get file information.\n");
}
}


HANDLE OpenBinaryFile(const char *filename) {
    HANDLE hFile = CreateFile(
    filename,
    GENERIC_READ,
    FILE_SHARE_READ,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    NULL
    );
if (hFile == INVALID_HANDLE_VALUE)
{
    printf("Couldn't open the file.\n");
    return INVALID_HANDLE_VALUE;}
    return hFile;

    }


void HexDump(HANDLE hFile){
    BYTE buffer[BYTES_PER_LINE];
DWORD bytesRead;

LARGE_INTEGER current;
LARGE_INTEGER zero = {0};

SetFilePointerEx(
    hFile,
    zero,
    &current,
    FILE_CURRENT
);

ULONGLONG offset = current.QuadPart;

while(ReadFile(hFile, buffer, BYTES_PER_LINE, &bytesRead, NULL) && bytesRead > 0){
    printf("%016llX  ", offset);
    for (DWORD i = 0; i < bytesRead; i++)
    {
        printf("%02X ", buffer[i]);
    }
    printf("  ");

    for (DWORD i = 0; i < bytesRead; i++)
    {
        printf("%c", (buffer[i] >= 32 && buffer[i] <= 126 ? buffer[i] : '.'));
    }
    printf("\n");

    offset += bytesRead;
}
}


BOOL JumpToOffset(HANDLE hFile){
    LARGE_INTEGER offset;
    printf("Enter an offset (hex): \n");
    
    if (scanf("%llx", &offset.QuadPart) != 1)
        return FALSE;

    if (!SetFilePointerEx(hFile, offset, NULL, FILE_BEGIN))
        return FALSE;

    printf("Moved to offset 0x%llX\n", offset.QuadPart);

    return TRUE;
}



void DetectFileType(HANDLE hFile){
    BYTE signature[8];
    DWORD bytesRead;

    LARGE_INTEGER zero = {0};
    if (!SetFilePointerEx(
        hFile,
        zero,
        NULL,
        FILE_BEGIN))
    {
        printf("Couldn't seek to beginning.\n");
        return;
    }
    if(!ReadFile(
    hFile,
    signature,
    sizeof(signature),
    &bytesRead,
    NULL)){
        printf("Couldn't read the file.\n");
    return;
    }
     if (bytesRead < 2){
        printf("File is too small.\n");
        return;
    }
if(signature[0] == 0x4D && signature[1] == 0x5A){
    printf("Windows Portable Executable (EXE/DLL)\n");
}
else{
    printf("Unknown file type.\n");
}
}


void ParseDOSHeader(HANDLE hFile){
    if(hFile == INVALID_HANDLE_VALUE) 
    return;
    IMAGE_DOS_HEADER dosHeader;
    DWORD bytesRead;
    LARGE_INTEGER zero = {0};
    if(!SetFilePointerEx(
    hFile,
    zero,
    NULL,
    FILE_BEGIN))
    {
        printf("Failed to seek to file starts.\n");
        return;
    }
    if(!ReadFile(
    hFile,
    &dosHeader,
    sizeof(dosHeader),
    &bytesRead,
    NULL))

{
        printf("Failed to read DOS header.\n");
        return;
    }

    if (bytesRead != sizeof(dosHeader))
    {
        printf("Incomplete DOS header.\n");
        return;
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("Not a valid PE executable.\n");
        return;
    }

    printf("\n=== DOS Header ===\n");
    printf("Magic: 0x%04X (%c%c)\n",
       dosHeader.e_magic,
       dosHeader.e_magic & 0xFF,
       dosHeader.e_magic >> 8);

    printf("e_lfanew (PE Header Offset): 0x%X\n",
           dosHeader.e_lfanew);

}

DWORD RvaToFileOffset(
    DWORD rva,
    IMAGE_SECTION_HEADER sections[],
    WORD numberOfSections)
{
    for (WORD i = 0; i < numberOfSections; i++)
    {
        DWORD size = sections[i].Misc.VirtualSize;

        if (size == 0)
            size = sections[i].SizeOfRawData;

        if (rva >= sections[i].VirtualAddress &&
            rva < sections[i].VirtualAddress + size)
        {
            return (rva - sections[i].VirtualAddress)
                 + sections[i].PointerToRawData;
        }
    }

    return 0;
}

void ParsePEHeader(HANDLE hFile){
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_FILE_HEADER fileHeader;
    IMAGE_OPTIONAL_HEADER32 optionalHeader;
    IMAGE_SECTION_HEADER sections[MAX_SECTIONS];

    DWORD bytesRead;
    LARGE_INTEGER zero = {0};
    
    
    if (!SetFilePointerEx(hFile, zero, NULL, FILE_BEGIN)) {
        printf("Failed to seek to beginning.\n");
        return;
    }
    
    
    if (!ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, NULL)) {
        printf("Failed to read DOS header.\n");
        return;
    }
    
    if (bytesRead != sizeof(dosHeader)) {
        printf("Incomplete DOS header.\n");
        return;
    }
    
    
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Not a valid PE executable.\n");
        return;
    }
    
    printf("\nDOS Header e_lfanew: 0x%X\n", dosHeader.e_lfanew);
    
    
    LARGE_INTEGER peOffset;
    peOffset.QuadPart = dosHeader.e_lfanew;
    
    
    if (!SetFilePointerEx(hFile, peOffset, NULL, FILE_BEGIN)) {
        printf("Failed to seek to PE header.\n");
        return;
    }
    
    
    BYTE peSignature[4];
    if (!ReadFile(hFile, peSignature, 4, &bytesRead, NULL)) {
        printf("Failed to read PE signature.\n");
        return;
    }
    
    if (bytesRead != 4) {
        printf("Incomplete PE signature read.\n");
        return;
    }
    
    
    printf("\nPE Signature (hex): ");
    for (int i = 0; i < 4; i++) {
        printf("%02X ", peSignature[i]);
    }
    printf("\n");
    
    
    printf("PE Signature (chars): ");
    for (int i = 0; i < 4; i++) {
        printf("%c", (peSignature[i] >= 32 && peSignature[i] <= 126 ? peSignature[i] : '.'));
    }
    printf("\n");

   
    if(!ReadFile(hFile, &fileHeader, sizeof(fileHeader), &bytesRead, NULL)){
    printf("Failed to read IMAGE_FILE_HEADER\n");
    return;
       }
     if (bytesRead != sizeof(fileHeader)){
    printf("Incomplete IMAGE_FILE_HEADER\n");
    }
    printf("\n=== IMAGE_FILE_HEADER ===\n");

    printf("Machine: 0x%04X ", fileHeader.Machine);

    switch (fileHeader.Machine){
    case IMAGE_FILE_MACHINE_AMD64:
        printf("(AMD64 / x64)");
        break;

    case IMAGE_FILE_MACHINE_I386:
        printf("(I386 / x86)");
        break;

    default:
        printf("(Unknown)");
        break;
    }

    printf("\n");

    printf("Number of Sections: %u\n",
       fileHeader.NumberOfSections);

    printf("TimeDateStamp: 0x%08X\n",
       fileHeader.TimeDateStamp);

    printf("Size of Optional Header: %u\n",
       fileHeader.SizeOfOptionalHeader);


    printf("Characteristics: 0x%04X\n",
       fileHeader.Characteristics);


    if(!ReadFile(hFile, &optionalHeader, sizeof(optionalHeader), &bytesRead, NULL))
    {
 printf("Failed to read IMAGE_OPTIONAL_HEADER\n");
    return;
    }
    if (bytesRead != sizeof(optionalHeader)){
    printf("Incomplete IMAGE_OPTIONAL_HEADER\n");
    }

    printf("\n=== IMAGE_OPTIONAL_HEADER ===\n");
    printf("AddressOfEntryPoint : 0x%08X\n",
       optionalHeader.AddressOfEntryPoint);

    printf("ImageBase: 0x%016llX\n",
       optionalHeader.ImageBase);

    printf("Subsystem: 0x%04X ",
       optionalHeader.Subsystem);

    switch(optionalHeader.Subsystem){
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:
        printf("(Windows GUI)\n");
        break;

    case IMAGE_SUBSYSTEM_WINDOWS_CUI:
        printf("(Console)\n");
        break;

    default:
        printf("(Unknown)\n");
    } 

    printf("Section Alignment: 0x%08X\n",
       optionalHeader.SectionAlignment);

    printf("File Alignment: 0x%08X\n",
       optionalHeader.FileAlignment);

    printf("Size of Image: 0x%08X\n",
       optionalHeader.SizeOfImage);
    


  
    for (int i = 0; i < fileHeader.NumberOfSections; i++){
    if(!ReadFile(hFile, &sections[i], sizeof(IMAGE_SECTION_HEADER), &bytesRead, NULL)){
    printf("Failed to read IMAGE_SECTION_HEADER\n");
    return; 
    }
    if (bytesRead != sizeof(sections[i]))
   {
    printf("Incomplete IMAGE_SECTION_HEADER\n");
    return;
    }
     printf("\n=== Section %d ===\n", i + 1);

     printf("Name: %.8s\n", sections[i].Name);

    printf("Virtual Address : 0x%08X\n",
       sections[i].VirtualAddress);

    printf("Virtual Size    : 0x%08X\n",
       sections[i].Misc.VirtualSize);

   printf("Raw Offset      : 0x%08X\n",
       sections[i].PointerToRawData);

   printf("Raw Size        : 0x%08X\n",
       sections[i].SizeOfRawData);

   printf("Characteristics : 0x%08X\n",
       sections[i].Characteristics);
  }

DWORD fileOffset = RvaToFileOffset(
    optionalHeader.AddressOfEntryPoint,
    sections,
    fileHeader.NumberOfSections
);
printf("\nRVA: 0x%08X\n", optionalHeader.AddressOfEntryPoint);
printf("Entry Point File Offset: 0x%08X\n", fileOffset);
}


void ShowMenu(void)
{
    printf("\n");
    printf("1. Detect file type\n");
    printf("2. DOS Header\n");
    printf("3. Parse PE\n");
    printf("4. Dump from beginning\n");
    printf("5. Jump to offset and dump\n");
    printf("6. Exit\n");
}
    

int main(void) {
    char files[MAX_FILES][MAX_PATH];

   int count = ListFiles(files);

if (count <= 0)
    return 1;

int choice = ChooseFile(count);

    PrintFileInfo(files[choice]);

    HANDLE hFile = OpenBinaryFile(files[choice]);

if (hFile == INVALID_HANDLE_VALUE)
    return 1;


int option;
BOOL running = TRUE;

while(running){
 ShowMenu();

 printf("Choice: ");
 scanf("%d", &option);

 switch(option)
 {
 case 1:
    DetectFileType(hFile);
    break;
case 2:
    ParseDOSHeader(hFile);
    break;
case 3:
    ParsePEHeader(hFile);
    break;
case 4:
    {
        LARGE_INTEGER zero = {0};

    if (!SetFilePointerEx(
        hFile,
        zero,
        NULL,
        FILE_BEGIN))
    {
        printf("Couldn't seek.\n");
        break;
    }
    HexDump(hFile);
    break;
}
case 5:
    if(JumpToOffset(hFile))
        HexDump(hFile);
    break;

case 6:
    running = FALSE;
    break;

default:
    printf("Invalid option.\n");

 }
}

CloseHandle(hFile);
return 0;
}




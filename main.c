#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <winnt.h>

#define MAX_FILES 100
#define BYTES_PER_LINE 16
#define MAX_SECTIONS 96

typedef struct
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_FILE_HEADER fileHeader;
    IMAGE_OPTIONAL_HEADER32 optionalHeader;
    BOOL isPE64;
    IMAGE_OPTIONAL_HEADER64 optional64;
    IMAGE_SECTION_HEADER sections[MAX_SECTIONS];

} PEFile;

int ListFiles(char files[][MAX_PATH]);
int ChooseFile(int count);
void PrintFileInfo(const char *filename);
HANDLE OpenBinaryFile(const char *filename);
void HexDump(HANDLE hFile);
BOOL JumpToOffset(HANDLE hFile);
void DetectFileType(HANDLE hFile);
void ParseDOSHeader(HANDLE hFile);
void ParsePE(HANDLE hFile);
DWORD RvaToFileOffset(DWORD rva,const IMAGE_SECTION_HEADER sections[], WORD numberOfSections);
BOOL SeekFile(HANDLE hFile, LONGLONG offset);
BOOL ReadBytes(HANDLE hFile, void *buffer, DWORD size);
BOOL ReadDOSHeader(HANDLE hFile, PEFile *pe);
BOOL ReadPESignature(HANDLE hFile, BYTE signature[4], PEFile *pe);
BOOL ReadFileHeader(HANDLE hFile, PEFile *pe);
BOOL ReadOptionalHeader(HANDLE hFile, PEFile *pe);
BOOL ReadSectionHeaders(HANDLE hFile, PEFile *pe);
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


int ChooseFile(int count)
{
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

if (GetFileAttributesEx(filename,GetFileExInfoStandard,&data))
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


HANDLE OpenBinaryFile(const char *filename) 
{
    HANDLE hFile = CreateFile(filename,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
if (hFile == INVALID_HANDLE_VALUE)
{
    printf("Couldn't open the file.\n");
    return INVALID_HANDLE_VALUE;}
    return hFile;

}

BOOL SeekFile(HANDLE hFile, LONGLONG offset)
{
    LARGE_INTEGER pos;
    pos.QuadPart = offset;

    return SetFilePointerEx(hFile,pos,NULL,FILE_BEGIN);
}

BOOL ReadBytes(HANDLE hFile,void *buffer,DWORD size)
{
    DWORD bytesRead;

    if (!ReadFile(hFile,buffer,size,&bytesRead,NULL))
    {
        return FALSE;
    }

    return bytesRead == size;
}


void HexDump(HANDLE hFile){
    BYTE buffer[BYTES_PER_LINE];
DWORD bytesRead;

LARGE_INTEGER current;
LARGE_INTEGER zero = {0};

SetFilePointerEx(hFile,zero,&current,FILE_CURRENT);

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

    if (!SeekFile(hFile, 0))
    {
    printf("Couldn't seek to beginning.\n");
        return;
    }

if (!ReadBytes(hFile,signature,sizeof(signature)))
    {
    printf("Couldn't read the file.\n");
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

if (!SeekFile(hFile, 0))
{
    printf("Couldn't seek.\n");
    return;
}
if (!ReadBytes(hFile,&dosHeader,sizeof(dosHeader)))
{
    printf("Couldn't read DOS header.\n");
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
    const IMAGE_SECTION_HEADER sections[],
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


BOOL ReadDOSHeader(HANDLE hFile, PEFile *pe)
{
    if (!SeekFile(hFile, 0))
        return FALSE;
    if (!ReadBytes(hFile,&pe->dosHeader,sizeof(pe->dosHeader)))
        return FALSE;
    return pe->dosHeader.e_magic == IMAGE_DOS_SIGNATURE;
}

BOOL ReadPESignature(HANDLE hFile, BYTE signature[4], PEFile *pe)
{
    if (!SeekFile(hFile, pe->dosHeader.e_lfanew))
        return FALSE;
    return ReadBytes(hFile,signature,4);
}

BOOL ReadFileHeader(HANDLE hFile, PEFile *pe)
{
    return ReadBytes(hFile,&pe->fileHeader,sizeof(pe->fileHeader));
}


BOOL ReadOptionalHeader(HANDLE hFile, PEFile *pe)
{
    WORD magic;
    if (!ReadBytes(hFile, &magic, sizeof(magic)))
        return FALSE;
    LARGE_INTEGER back;
    back.QuadPart = -2;

    SetFilePointerEx(hFile,back,NULL,FILE_CURRENT);

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        pe->isPE64 = FALSE;
        return ReadBytes(hFile,&pe->optionalHeader,sizeof(pe->optionalHeader));
    }

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        pe->isPE64 = TRUE;
        return ReadBytes(hFile,&pe->optional64,sizeof(pe->optional64));
    }
    return FALSE;
}


BOOL ReadSectionHeaders(HANDLE hFile, PEFile *pe)
{
    if (pe->fileHeader.NumberOfSections > MAX_SECTIONS)
  {
    printf("Too many sections.\n");
    return FALSE;
  }
    for (WORD i = 0;
         i < pe->fileHeader.NumberOfSections;i++)
    {
        if (!ReadBytes(hFile,&pe->sections[i],sizeof(pe->sections[i])))
        {
            return FALSE;
        }
    }
    return TRUE;
}


DWORD GetEntryPoint(const PEFile *pe)
{
    return pe->isPE64
        ? pe->optional64.AddressOfEntryPoint
        : pe->optionalHeader.AddressOfEntryPoint;
}
DWORD GetSubsystem(const PEFile *pe)
{
    return pe->isPE64
        ? pe->optional64.Subsystem
        : pe->optionalHeader.Subsystem;
}
ULONGLONG GetImageBase(const PEFile *pe)
{
    return pe->isPE64
        ? pe->optional64.ImageBase
        : pe->optionalHeader.ImageBase;
}
DWORD GetSectionAlignment(const PEFile *pe)
{
    return pe->isPE64
        ? pe->optional64.SectionAlignment
        : pe->optionalHeader.SectionAlignment;
}
DWORD GetFileAlignment(const PEFile *pe)
{
    return pe->isPE64
        ? pe->optional64.FileAlignment
        : pe->optionalHeader.FileAlignment;
}
DWORD GetSizeOfImage(const PEFile *pe)
{
    return pe->isPE64
        ? pe->optional64.SizeOfImage
        : pe->optionalHeader.SizeOfImage;  
}



void ParsePE(HANDLE hFile)
{
    PEFile pe;
    BYTE peSignature[4];

    if (!ReadDOSHeader(hFile, &pe))
    {
        printf("Invalid DOS header.\n");
        return;
    }
    if (!ReadPESignature(hFile, peSignature, &pe))
        return;
    if (!ReadFileHeader(hFile, &pe))
        return;
    if (!ReadOptionalHeader(hFile, &pe))
        return;
    if (!ReadSectionHeaders(hFile, &pe))
        return;

    
    printf("\nDOS Header e_lfanew: 0x%X\n", pe.dosHeader.e_lfanew);
    
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
   

    printf("\n=== IMAGE_FILE_HEADER ===\n");
    printf("Machine: 0x%04X\n", pe.fileHeader.Machine);
   printf("Format: %s\n",
       pe.isPE64 ? "PE32+" : "PE32");
    printf("\n");
    printf("Number of Sections: %u\n",
       pe.fileHeader.NumberOfSections);
    printf("TimeDateStamp: 0x%08X\n",
       pe.fileHeader.TimeDateStamp);
    printf("Size of Optional Header: %u\n",
       pe.fileHeader.SizeOfOptionalHeader);
    printf("Characteristics: 0x%04X\n",
       pe.fileHeader.Characteristics);


    printf("\n=== IMAGE_OPTIONAL_HEADER ===\n");

    printf("Image Base : 0x%llX\n",GetImageBase(&pe));
    printf("Entry Point: 0x%X\n",GetEntryPoint(&pe));
    printf("Subsystem  : %u\n",GetSubsystem(&pe));
    printf("Section Alignment: 0x%08X\n",GetSectionAlignment(&pe));
    printf("File Alignment: 0x%08X\n",GetFileAlignment(&pe));
    printf("Size of Image: 0x%08X\n",GetSizeOfImage(&pe));
    
  
  for (WORD i = 0;i < pe.fileHeader.NumberOfSections;i++)
    {
     printf("\n=== Section %d ===\n", i + 1);
     printf("Name: %.8s\n", pe.sections[i].Name);
     printf("Virtual Address : 0x%08X\n",
       pe.sections[i].VirtualAddress);
     printf("Virtual Size    : 0x%08X\n",
       pe.sections[i].Misc.VirtualSize);
     printf("Raw Offset      : 0x%08X\n",
       pe.sections[i].PointerToRawData);
     printf("Raw Size        : 0x%08X\n",
       pe.sections[i].SizeOfRawData);
     printf("Characteristics : 0x%08X\n",
       pe.sections[i].Characteristics);
    }


  DWORD entryPoint = GetEntryPoint(&pe);
 
  DWORD fileOffset = RvaToFileOffset(entryPoint,pe.sections,pe.fileHeader.NumberOfSections);

  printf("\nRVA: 0x%08X\n", entryPoint);
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
    ParsePE(hFile);
    break;
case 4:
{
    if (!SeekFile(hFile, 0))
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




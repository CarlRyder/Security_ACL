// Made by Y. Sendov. April 2022

#define _CRT_SECURE_NO_WARNINGS
#define DEFAULT_ERROR -1

#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <accctrl.h>
#include <aclapi.h>

int security(char input[3])
{
	int flag = 0;
	if (input[0] == '\n') return 1;
	input[strcspn(input, "\n")] = 0;
	for (unsigned int i = 0; i < strlen(input); i++)
	{
		if (input[i] < 48 || input[i] > 57)
		{
			flag = 1;
			break;
		}
	}
	return flag;
}

int input_num()
{
	int value = -1;
	char input[3];
	fgets(input, 3, stdin);
	input[strcspn(input, "\n")] = 0;
	fseek(stdin, 0, SEEK_END);
	if (security(input) == 0 && atoi(input) < 10)
	{
		value = atoi(input);
		return value;
	}
	else return -1;
}

void create_file()
{
	FILE* file = fopen("C:\\Users\\Professional\\Desktop\\LAB12\\testing\\text.txt", "w");
	if (file == NULL)
	{
		printf("The specified directory was not found!\nCheck the file path and try again.\n");
		exit(DEFAULT_ERROR);
	}
	fclose(file);
	printf("The file was created successfully!\n");
}

void read_file()
{
	FILE* file = fopen("C:\\Users\\Professional\\Desktop\\LAB12\\testing\\text.txt", "r");
	if (file == NULL)
	{
		printf("The specified directory was not found!\nCheck the file path and try again.\n");
		exit(DEFAULT_ERROR);
	}
	char symbol;
	printf("File ñontents:\n\n");
	while (!feof(file))
	{
		symbol = fgetc(file);
		if (symbol == EOF) break;
		printf("%c", symbol);
	}
	printf("\n");
	fclose(file);
}

void edit_file()
{
	FILE* file = fopen("C:\\Users\\Professional\\Desktop\\LAB12\\testing\\text.txt", "a");
	if (file == NULL)
	{
		printf("The specified directory was not found!\nCheck the file path and try again.\n");
		exit(DEFAULT_ERROR);
	}
	printf("Warning! You can enter a string of no more than 100 characters.\nFurther characters will not be read.\n\n");
	char str[100];
	fgets(str, sizeof(str), stdin);
	str[strcspn(str, "\n")] = 0;
	fseek(stdin, 0, SEEK_END);
	fputs(str, file);
	fclose(file);
}

DWORD add_ace(LPTSTR pszObjName, SE_OBJECT_TYPE ObjectType, LPTSTR pszTrustee, TRUSTEE_FORM TrusteeForm, DWORD dwAccessRights, ACCESS_MODE AccessMode, DWORD dwInheritance)
{
	DWORD dwRes = 0;
	PACL pOldDACL = NULL, pNewDACL = NULL; // The pointer to the ACL structure is the header of the access control list (ACL)
	PSECURITY_DESCRIPTOR pSD = NULL; // Pointer to the security descriptor structure
	EXPLICIT_ACCESS ea; // The EXPLICIT_ACCESS structure defines access control information for the specified proxy
	if (pszObjName == NULL) return ERROR_INVALID_PARAMETER;
	// Getting copies of the Security descriptor
	dwRes = GetNamedSecurityInfo(pszObjName, ObjectType, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDACL, NULL, &pSD);
	if (dwRes != ERROR_SUCCESS)
	{
		printf("GetNamedSecurityInfo error - %u\n", dwRes);
		goto Clear;
	}
	// Initializing the EXPLICIT_ACCESS structure for the new ACE
	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea.grfAccessPermissions = dwAccessRights;
	ea.grfAccessMode = AccessMode;
	ea.grfInheritance = dwInheritance;
	ea.Trustee.TrusteeForm = TrusteeForm;
	ea.Trustee.ptstrName = pszTrustee;
	// Creating a new ACE that merges with the ACL
	dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL); // Creating a new Access Control List (ACL) by merging new management information into an existing ACL structure
	if (ERROR_SUCCESS != dwRes)
	{
		printf("SetEntriesInAcl error - %u\n", dwRes);
		goto Clear;
	}
	// Attaching a new ACE as a DACL object
	dwRes = SetNamedSecurityInfo(pszObjName, ObjectType, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL);
	if (ERROR_SUCCESS != dwRes) 
	{
		printf("SetNamedSecurityInfo error - %u\n", dwRes);
		goto Clear;
	}
	Clear:
	if (pSD != NULL) LocalFree((HLOCAL)pSD);
	if (pNewDACL != NULL) LocalFree((HLOCAL)pNewDACL);
	return dwRes;
}

void edit_attribute()
{
	int marker = 1;
	printf("Select the number of the required operation:\n\n");
	printf("1. Grant rights to the user\n"
		"2. Remove all rights\n"
		"3. Grant read permissions\n"
		"4. Remove read permissions\n"
		"5. Grant recording rights\n6. Remove recording rights\n7. Grant deletion rights\n8. Remove deletion rights\n0. Exit to the menu\n");
	printf("\nÂâåäèòå íîìåð ïóíêòà: ");
	int number = input_num();
	if (number != -1 && number < 9)
	{
		while (marker)
		{
			switch (number)
			{
			case 0:
				marker = 0;
				break;
			case 1:
				add_ace(TEXT("C:\\Users\\Professional\\Desktop\\LAB12\\testing\\text.txt"), SE_FILE_OBJECT, TEXT("Professional"), TRUSTEE_IS_NAME, GENERIC_ALL, SET_ACCESS, NO_INHERITANCE);
				break;
			case 2:
				add_ace(TEXT("C:\\Users\\Professional\\Desktop\\LAB12\\testing\\text.txt"), SE_FILE_OBJECT, TEXT("Professional"), TRUSTEE_IS_NAME, GENERIC_ALL, DENY_ACCESS, NO_INHERITANCE);
				break;
			case 3:
				add_ace(TEXT("C:\\Users\\Professional\\Desktop\\LAB12\\testing\\text.txt"), SE_FILE_OBJECT, TEXT("Professional"), TRUSTEE_IS_NAME, GENERIC_READ, SET_ACCESS, NO_INHERITANCE);
				break;
			case 4:
				add_ace(TEXT("C:\\Users\\Professional\\Desktop\\LAB12\\testing\\text.txt"), SE_FILE_OBJECT, TEXT("Professional"), TRUSTEE_IS_NAME, GENERIC_READ, DENY_ACCESS, NO_INHERITANCE);
				break;
			case 5:
				add_ace(TEXT("C:\\Users\\Professional\\Desktop\\LAB12\\testing\\text.txt"), SE_FILE_OBJECT, TEXT("Professional"), TRUSTEE_IS_NAME, GENERIC_WRITE, SET_ACCESS, NO_INHERITANCE);
				break;
			case 6:
				add_ace(TEXT("C:\\Users\\Professional\\Desktop\\LAB12\\testing\\text.txt"), SE_FILE_OBJECT, TEXT("Professional"), TRUSTEE_IS_NAME, GENERIC_WRITE, DENY_ACCESS, NO_INHERITANCE);
				break;
			case 7:
				add_ace(TEXT("C:\\Users\\Professional\\Desktop\\LAB12\\testing\\text.txt"), SE_FILE_OBJECT, TEXT("Professional"), TRUSTEE_IS_NAME, DELETE, SET_ACCESS, NO_INHERITANCE);
				break;
			case 8:
				add_ace(TEXT("C:\\Users\\Professional\\Desktop\\LAB12\\testing\\text.txt"), SE_FILE_OBJECT, TEXT("Professional"), TRUSTEE_IS_NAME, DELETE, DENY_ACCESS, NO_INHERITANCE);
				break;
			}
			if (marker)
			{
				printf("Completed successfully. Enter the number of the next item: ");
				int number = input_num();
				if (number == 0)
				{
					system("cls");
					break;
				}
			}
		}
	}
	else
	{
		system("cls");
		printf("You entered the item number incorrectly, try again.\n");
	}
}

int programm_menu()
{
	printf("Select the operating mode of the program:\n\n");
	printf("1. Creating a file\n2. Reading a file\n3. Changing a file\n4. Changing file Security attributes.\n5. Exiting the program\n\n");
	printf("Enter the number of the program's operating mode: ");

	int number = input_num();
	if (number < 6) return number;
	else return -1;
}

int main()
{
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);

	int n = programm_menu();
	while (n != 5)
	{
		switch (n)
		{
		case 1:
			system("cls");
			create_file();
			break;
		case 2:
			system("cls");
			read_file();
			break;
		case 3:
			system("cls");
			edit_file();
			break;
		case 4:
			system("cls");
			edit_attribute();
			printf("File security attributes have been successfully changed!\n");
			break;
		default:
			system("cls");
			printf("You entered the item number incorrectly, try again.\n");
			break;
		}
		printf("\n");
		n = programm_menu();
	}
	return 0;
}
#include<Windows.h>
#include<stdio.h>

VOID ObfuscateString(unsigned char* input, unsigned char* output) {
	char key[] = "abcdefghilmnopqrstuvzy";
	size_t input_length = strlen(input);
	size_t key_size = strlen(key);
	for (int x = 0; x < input_length; x++) {
		char i[] = { input[x] , "\0" };
		int index = strcspn(key, i);
		index = (index + 5) % key_size;
		i[0] = key[index];
		*output = i[0];
		output++;
	}
}

VOID DeobfuscateString(unsigned char* input, unsigned char* output) {
	char key[] = "abcdefghilmnopqrstuvzy";
	size_t key_size = strlen(key);
	size_t input_length = strlen(input);
	for (int x = 0; x < input_length; x++) {
		char i[] = { input[x] , "\0" };
		int index = strcspn(key, i);
		index = index - 5;
		if (index < 0)
			index = key_size - abs(index);
		i[0] = key[index];
		*output = i[0];
		output++;
	}

}

void PrintString(LPCSTR Name, unsigned char* data, size_t data_size) {
	printf("%s: ", Name);
	for (int i = 0; i < data_size; i++) {
		printf("%c", data[i]);
	}
	printf("\n");

}

int main()
{
	unsigned char text1[] = "ylhbzpae"; //security
	unsigned char text2[] = "bsipynbpyli"; // undisguised
	unsigned char text3[] = "tgmbyhfapts"; //obfuscation
	
	size_t text_size = strlen(text1);
	unsigned char* deobfuscated_text = (char*)malloc(sizeof(char*) * (text_size + 10));
	DeobfuscateString("ylhbzpae", deobfuscated_text);
	PrintString("deobfuscated String", deobfuscated_text, text_size);

	size_t text2_size = strlen(text2);
	deobfuscated_text = (char*)realloc(NULL, text2_size + 10);
	DeobfuscateString("bsipynbpyli", deobfuscated_text);
	PrintString("deobfuscated String", deobfuscated_text, text2_size);


	/*
	size_t text2_size = strlen(text2);
	obfuscated_text = (char*)realloc(NULL, text2_size + 10);
	deobfuscated_text = (char*)realloc(NULL, text2_size + 10);
	ObfuscateString(text2, obfuscated_text);
	PrintString("obfuscated String", obfuscated_text, text2_size);
	DeobfuscateString(obfuscated_text, deobfuscated_text);
	PrintString("deobfuscated String", deobfuscated_text, text2_size);
	*/

}
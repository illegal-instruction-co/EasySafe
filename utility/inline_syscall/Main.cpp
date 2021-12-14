#include <iostream>
#include <EasySafe.hpp>

int main() {

	/*
	* Start EasySafe
	* --------------
	* First parameter is the payload
	* --------------
	* struct Payload;
	*/

	auto instance = (new II::EasySafe({ true }))->Init();

	return 0;
}
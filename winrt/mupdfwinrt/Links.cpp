#include "pch.h"
#include "Links.h"

using namespace mupdfwinrt;

Links::Links(void)
{
	this->uri = nullptr;
	this->page_num = -1;
	this->type = NOT_SET;
}

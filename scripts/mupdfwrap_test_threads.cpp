#include "mupdf/classes2.h"

#include <assert.h>
#include <thread>

#include <mutex>

std::mutex s_mutex;


static void threadfn(int threadnum, std::vector<mupdf::PdfDocument>& documents)
{
    for (int i=0; i<100; ++i)
    {
        {
            std::lock_guard<std::mutex> lock(s_mutex);
            std::cout
                    << "[" << threadnum << "]:"
                    << " i=" << i
                    << std::endl;
        }
        int j=0;

        std::vector<mupdf::PdfDocument> documents2;
        {
            std::lock_guard<std::mutex> lock(s_mutex);
            documents2 = documents;
        }
        for (auto& document: documents2)
        {
            if (0)
            {
                std::lock_guard<std::mutex> lock(s_mutex);
                std::cout
                        << "[" << threadnum << "]:"
                        << " i=" << i
                        << " j=" << j
                        << std::endl;
            }
            mupdf::FzRect mediabox(0, 0, 500, 300);
            //auto resources = mupdf::pdf_add_new_dict(document, 1);
            mupdf::PdfObj resources;
            auto contents = mupdf::FzBuffer();
            assert(document.m_internal);
            auto page = mupdf::pdf_add_page(document, mediabox, 0, resources, contents);
            mupdf::pdf_insert_page(document, 0, page);
            try
            {
                mupdf::pdf_delete_page(document, 0);
            }
            catch (std::exception& e)
            {
                std::lock_guard<std::mutex> lock(s_mutex);
                std::cout << "[" << threadnum << "]:" << " pdf_delete_page() => " << e.what() << std::endl;
            }
            j += 1;
        }
    }
}


static int threadfn0_x = 0;

static void threadfn0(int i)
{
    if (i)
    {
        std::lock_guard<std::mutex> lock(s_mutex);

        threadfn0_x += 1;
    }
    else
    {
        threadfn0_x += 1;
    }
}

int main(int argc, char** argv)
{
    if (0)
    {
        std::vector<std::thread> threads;
        threads.push_back(std::thread(threadfn0, 0));
        threads.push_back(std::thread(threadfn0, 1));
        for (auto& thread: threads)
        {
            thread.join();
        }

        return 0;
    }

    for (int i=1; i<argc; ++i)
    {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
        {
            std::cout << "Args:\n"
                    << "    -l\n"
                    << "        Disable locking.\n"
                    << "    -L\n"
                    << "        Enable locking.\n"
                    << "    -t\n"
                    << "        Use single fz_context for all threads and disable locking.\n"
                    ;
            return 0;
        }
        else if (!strcmp(argv[i], "-l"))   mupdf::use_locking(false);
        else if (!strcmp(argv[i], "-L"))   mupdf::use_locking(true);
        else if (!strcmp(argv[i], "-t"))   mupdf::reinit_singlethreaded();
        else
        {
            std::cout << "Unrecognised argv[i]=" << argv[i] << "\n";
            return 1;
        }
    }

    std::vector<mupdf::PdfDocument> documents;
    {
        std::lock_guard<std::mutex> lock(s_mutex);
        for (int i=0; i<10; ++i)
        {
            documents.push_back(mupdf::PdfDocument());
        }
    }
    std::vector<std::thread> threads;
    for (int i=0; i<30; ++i)
    {
        threads.push_back(std::thread(threadfn, i, std::ref(documents)));
    }

    for (auto& thread: threads)
    {
        thread.join();
    }
    return 0;
}

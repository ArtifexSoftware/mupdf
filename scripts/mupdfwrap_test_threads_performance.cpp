#include "mupdf/classes2.h"

#include <assert.h>
#include <thread>

#include <condition_variable>
#include <mutex>
#include <queue>
#include <chrono>

std::mutex s_mutex;


template <class T>
class SafeQueue
{
public:
  SafeQueue(void)
    : q()
    , m()
    , c()
  {}

  ~SafeQueue(void)
  {}

  // Add an element to the queue.
  void put(T t)
  {
    std::lock_guard<std::mutex> lock(m);
    q.push(t);
    c.notify_one();
  }

  // Get the "front"-element.
  // If the queue is empty, wait till a element is avaiable.
  T get(void)
  {
    std::unique_lock<std::mutex> lock(m);
    while(q.empty())
    {
      // release lock as long as the wait and reaquire it afterwards.
      c.wait(lock);
    }
    T val = q.front();
    q.pop();
    return val;
  }

private:
  std::queue<T> q;
  mutable std::mutex m;
  std::condition_variable c;
};

static SafeQueue<std::string> s_queue;


static void threadfn(int threadnum)
{
    for(;;)
    {
        std::string path = s_queue.get();
        if (path == "")
        {
            std::cout << "Thread " << threadnum << " finished" << std::endl;
            break;
        }
        std::cout << "Thread " << threadnum << " opening path " << path << std::endl;
        mupdf::FzDocument   document;
        try
        {
            document = mupdf::FzDocument(path.c_str());
        }
        catch (std::exception& e)
        {
            std::cout << "Thread " << threadnum << " failed to open " << path << ": " << e.what() << std::endl;
            continue;
        }
        int num_pages = document.fz_count_pages();
        for (int i=0; i<num_pages; ++i)
        {
            mupdf::FzPage page = mupdf::fz_load_page(document, i);
            mupdf::FzPixmap pixmap = mupdf::fz_new_pixmap_from_page_contents(
                    page,
                    mupdf::FzMatrix(),
                    mupdf::FzColorspace(mupdf::FzColorspace::Fixed_RGB),
                    1 /*alpha*/
                    );
        }
    }
    std::cout << "Thread " << threadnum << " finished" << std::endl;
    mupdf::FzOutput temp(mupdf::FzOutput::Fixed_STDOUT);
    mupdf::fz_dump_glyph_cache_stats(temp);
    temp.fz_close_output();
    fflush(stdout);
}


float doit(int num_threads, int num_documents, std::map<int, float>& num_threads_to_duration)
{
    auto t = std::chrono::steady_clock::now();

    std::string path = "thirdparty/zlib/doc/crc-doc.1.0.pdf";

    if (num_threads == 0)
    {
        mupdf::use_locking(false);
    }
    else
    {
        mupdf::use_locking(true);
    }

    std::vector<std::thread> threads;
    for (int i=0; i<num_threads; ++i)
    {
        threads.push_back(std::thread(threadfn, i));
    }

    for (int i=0; i<num_documents; ++i)
    {
        s_queue.put(path);
    }

    for (int i=0; i<num_threads; ++i)
    {
        s_queue.put("");
    }

    if (!num_threads)
    {
        threadfn(0);
    }

    for (auto& thread: threads)
    {
        thread.join();
    }

    auto dt = std::chrono::steady_clock::now() - t;
    float dtf = std::chrono::duration<double>(dt).count();
    num_threads_to_duration[num_threads] = dtf;
    return dtf;
}


int main(int argc, char** argv)
{
    system("pwd");
    std::string path = "thirdparty/zlib/doc/crc-doc.1.0.pdf";
    int num_documents = 20;
    std::map<int, float> num_threads_to_duration;

    if (argc == 2 && !strcmp(argv[1], "hotspot"))
    {
        doit(5 /*num_threads*/, num_documents, num_threads_to_duration);
    }
    else
    {
        doit( 5 /*num_threads*/, num_documents, num_threads_to_duration);
        doit(10 /*num_threads*/, num_documents, num_threads_to_duration);
        doit( 1 /*num_threads*/, num_documents, num_threads_to_duration);
        doit( 2 /*num_threads*/, num_documents, num_threads_to_duration);
    }

    for (auto it: num_threads_to_duration)
    {
        std::cout << "num_threads=" << it.first << ": time=" << it.second << "\n";
    }

    mupdf::FzOutput temp(mupdf::FzOutput::Fixed_STDOUT);
    mupdf::fz_dump_glyph_cache_stats(temp);
    temp.fz_close_output();

    return 0;
}

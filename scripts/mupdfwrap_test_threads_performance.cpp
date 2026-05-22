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
        auto document = mupdf::FzDocument(path.c_str());
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
}


std::chrono::steady_clock::duration doit(int num_threads, int num_documents)
{
    //time_t t = time(nullptr);
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

    //t = time(nullptr) - t;
    auto dt = std::chrono::steady_clock::now() - t;
    return dt;
}


int main(int argc, char** argv)
{
    std::string path = "thirdparty/zlib/doc/crc-doc.1.0.pdf";

    int num_documents = 80;
    auto t_1 = doit(1 /*num_threads*/, num_documents);
    auto t_2 = doit(2 /*num_threads*/, num_documents);
    auto t_5 = doit(5 /*num_threads*/, num_documents);
    auto t_10 = doit(10 /*num_threads*/, num_documents);
    std::cout << "t_1=" << std::chrono::duration<double>(t_1).count() << "\n";
    std::cout << "t_2=" << std::chrono::duration<double>(t_2).count() << "\n";
    std::cout << "t_5=" << std::chrono::duration<double>(t_5).count() << "\n";
    std::cout << "t_10=" << std::chrono::duration<double>(t_10).count() << "\n";
    return 0;
}

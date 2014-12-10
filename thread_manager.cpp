/* Copyright 2014 Damian Jarek
    This file is part of md5lamacz.

    md5lamacz is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    md5lamacz is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with md5lamacz.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "thread_manager.h"

void threadMain(const DictionaryIterator begin, const DictionaryIterator end, const PasswordMap& passwordHashes);/*
{

}*/

ThreadManager::ThreadManager(const PasswordMap& passwordHashes)
  : m_passwordHashes(passwordHashes)
{

}

ThreadManager::~ThreadManager()
{
  stopProducers();
  m_consumer.join();
}

void ThreadManager::launchConsumer()
{

}

void ThreadManager::launchProducers()
{
  auto n = std::max(std::thread::hardware_concurrency(), 1u);
  uint64_t wordsPerThread = dictionary.size()/n;

  auto begin = dictionary.begin();
  auto end = dictionary.begin() + wordsPerThread;
  if (wordsPerThread > 0) {
    for (uint32_t i = 0; i < n-1; ++i) {
      m_producers.emplace_back(std::bind(threadMain, begin, end, m_passwordHashes));
      begin += wordsPerThread;
      end += wordsPerThread;
    }
  }
  m_producers.emplace_back(std::bind(threadMain, begin, dictionary.end(), m_passwordHashes));
}

void ThreadManager::stopProducers()
{
  m_run.store(false);
  for (auto& thread : m_producers) {
    thread.join();
  }
}


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

#ifndef __THREAD_MANAGER_H__
#define __THREAD_MANAGER_H__

#include <thread>
#include <vector>
#include "hash.h"

typedef std::vector<std::string> DictionaryVec;
typedef DictionaryVec::const_iterator DictionaryIterator;

typedef std::vector<std::thread> ThreadVec;
typedef std::pair<std::string, Hash> ProducedHashPair;

class ThreadManager
{
public:
  ThreadManager(const PasswordMap& passwordHashes, const DictionaryVec& dictionary);
  ~ThreadManager();
  void launchProducers();
  void launchConsumer();
  void stopProducers();
  void stopAllThreads();
private:
  ThreadVec m_producers;
  std::thread m_consumer;
  const PasswordMap& m_passwordHashes;
  const DictionaryVec& m_dictionary;
};

#endif //__THREAD_MANAGER_H__
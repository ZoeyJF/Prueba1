/*
 * Copyright 2026 ZoeyJF
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Technical Description:
 * Implements high-speed Secp256k1 field arithmetic, Montgomery batch inversion,
 * and accelerated cryptographic hashing (SHA256, RIPEMD160, Keccak-256).
 */


#ifndef RANDOM_H
#define RANDOM_H

double rnd();
unsigned long rndl();
void rseed(unsigned long seed);

#endif

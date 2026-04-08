import 'dart:convert';

import 'package:crypto_keys_plus/crypto_keys.dart';
import 'package:jose_plus/jose.dart';
import 'package:test/test.dart';

void main() {
  group('JWA', () {
    test('Generating keys', () {
      var data = utf8.encode('hello world');

      for (var a in JsonWebAlgorithm.allAlgorithms) {
        print(a.name);
        var keyPair = a.generateCryptoKeyPair();

        var key = a.jwkFromCryptoKeyPair(keyPair);
        if (key == null) {
          throw UnimplementedError('Unkown key');
        }
        if (a.type == 'oct') {
          expect((key.cryptoKeyPair.publicKey as SymmetricKey).keyValue,
              (keyPair.publicKey as SymmetricKey).keyValue);
        } else {
          expect(key.cryptoKeyPair.publicKey, keyPair.publicKey);
          expect(key.cryptoKeyPair.privateKey, keyPair.privateKey);
        }

        // All generated keys should explicitly mark extractability.
        expect(key.extractable, isTrue);

        if (a.type == 'RSA') {
          final keyJson = key.toJson();
          expect(keyJson, containsPair('dp', isA<String>()));
          expect(keyJson, containsPair('dq', isA<String>()));
          expect(keyJson, containsPair('qi', isA<String>()));
        }

        switch (a.use) {
          case 'sig':
            expect(key.keyOperations, {'sign', 'verify'});
            var signature = key.sign(data);
            expect(key.verify(data, signature), isTrue);
            break;
          case 'enc':
            expect(key.keyOperations, {'encrypt', 'decrypt'});
            var encrypted = key.encrypt(data);
            expect(
                key.decrypt(encrypted.data,
                    initializationVector: encrypted.initializationVector,
                    additionalAuthenticatedData:
                        encrypted.additionalAuthenticatedData,
                    authenticationTag: encrypted.authenticationTag),
                data);
        }
      }
    });

    test('generateRandomKey for RSA includes CRT fields', () {
      final key = JsonWebAlgorithm.rs256.generateRandomKey();
      final keyJson = key.toJson();

      expect(keyJson, containsPair('dp', isA<String>()));
      expect(keyJson, containsPair('dq', isA<String>()));
      expect(keyJson, containsPair('qi', isA<String>()));
      expect(key.extractable, isTrue);
    });
  });
}

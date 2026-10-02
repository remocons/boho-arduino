# Boho for Arduino

[English](README.md) | [한국어](README.ko.md)

Boho는 Arduino용 데이터 암호화와 클라이언트–서버 인증을 제공합니다.
이름 **boho**는 ‘보호’를 뜻합니다.
[JavaScript용 Boho](https://github.com/remocons/boho)와 같은 패킷 형식을 사용하여
Node.js 서버 및 브라우저 클라이언트와 통신할 수 있습니다.

**현재 버전: 0.9.0**

Boho는 암호화 패킷을 처리합니다. 전송 수단, 메시지 프레이밍, 버퍼와 연결
수명주기는 응용 프로그램이 제공합니다. TCP, 직렬 통신, WebSocket, MQTT
페이로드와 저장 데이터에 사용할 수 있습니다. 완성된 메시징 클라이언트는
[IOSignal for Arduino](https://github.com/remocons/iosignal-arduino)를 참고하세요.

## 0.9.0 인증된 서버 시각 보정

서버 인증 후 검증된 `ENC_488` / `ENC_E2E` 헤더로 내장 시계를 경과시간의
최대 ±10% 속도로 보정합니다. 시간이 뒤로 이동하지 않으며 중복·오래된 서버
표본, 검증 실패 패킷과 내부 E2E 본문은 시계 보정에 사용하지 않습니다.
카운터 순환과 시간 보정 시에도 송신 시간·카운터 조합의 재사용을 방지합니다.
기존 패킷 형식은 유지합니다.

새 표본이 목표를 바꾸지 않는다면 1초 오차 보정에는 약 10초가 필요합니다.
전송 지연은 남으며 암호 메시지를 수신하지 않으면 새 보정이 없습니다.
정밀한 로컬 주기 측정은 `millis()`를 사용하세요. `getUnixTime()` 기반 타이머는
보정 중 빨라지거나 느려집니다. 큰 오차는 서버 정책에 따라 재연결이 필요할 수 있습니다.

## 왜 Boho인가요?

Boho는 DIY Arduino 장치, Node.js 서버, 직접 개발한 웹앱처럼 **양쪽 프로그램과
공유 비밀의 설정을 직접 관리하는 시스템**에 초점을 맞춥니다. 신뢰할 수 있는
설정 절차로 양쪽에 비밀을 전달할 수 있다면, 공유 키 인증과 대칭키 암호화가
통신을 보호하는 적합한 방법이 될 수 있습니다.

실제 개발에는 암호 알고리즘 선택뿐 아니라 인증, 패킷 형식, 장치와 브라우저의
호환 코드도 필요합니다. Boho는 SHA-256, XOR 키스트림과 공유 키 인증으로 이를
구성합니다. 차별점은 Arduino·JavaScript의 공통 구현과 응용 방식에 있습니다.
XOR와 사전 공유 키 자체는 이미 알려진 개념입니다.

### 사전 공유 키가 적합한 환경

| 환경 | 키 설정 경로의 예 |
| --- | --- |
| 직접 제작하고 설치하는 장치 | USB나 신뢰할 수 있는 직렬 설정 도구로 장치별 비밀 주입 |
| 웹앱과 개인 장치 | 별도 경로로 받은 비밀을 사용자가 입력하거나 신뢰할 수 있는 페어링 절차 사용 |
| 관리 주체가 같은 서버 | SSH, 기존 TLS 연결, 비밀 관리 시스템으로 비밀 배포 |

이런 환경에서는 인증기관 없이도 신뢰 관계를 만들 수 있습니다. 신뢰의 기반은
키 설정 경로와 양쪽 소프트웨어입니다. 키 보관·교체·폐기는 여전히 관리해야 합니다.
여러 장치가 같은 키를 쓰면 각 보유자가 같은 자격을 갖고 유출 영향도 커집니다.
브라우저의 공개 JavaScript 번들에 공통 비밀을 넣으면 비밀로 유지할 수 없습니다.

### XOR, 일회용 패드와 생성형 키스트림

XOR는 다음과 같이 되돌릴 수 있는 단순한 연산입니다.

```text
암호화: C = P XOR S
복호화: P = C XOR S

P: 평문, C: 암호문, S: 키스트림
```

진짜 일회용 패드(OTP)는 평문과 독립적인 완전한 무작위 패드를 데이터 길이만큼
준비하고, 비밀로 유지하며 한 번만 사용합니다. 이 조건에서는 완전한 비밀성을
얻습니다. 현실적인 어려움은 1MB 데이터마다 새로운 1MB 비밀 패드를 양쪽에
공급해야 한다는 점입니다. 짧은 고정 키의 반복은 이 성질을 제공하지 않습니다.
키스트림을 재사용하면 `C1 XOR C2 = P1 XOR P2` 관계가 노출됩니다.

Boho는 비밀 키와 메시지별 값에서 키스트림 블록을 생성합니다.
일반적인 `set_key()` 경로의 현재 구성은 다음과 같습니다.

```text
K  = SHA256(입력 키)
B  = SHA256(K || salt12)
S1 = SHA256(B || LE32(1))
S2 = SHA256(B || LE32(2))
…
S  = S1 || S2 || …       // 평문 길이만큼 사용
C  = P XOR S
```

`||`는 바이트열 연결이고 `LE32`는 4바이트 little-endian 정수입니다.
SHA-256 출력 하나는 32바이트입니다. 70바이트 메시지에는 두 블록 전체와
세 번째 블록의 앞 6바이트를 사용합니다. 복호화는 같은 키스트림을 다시 생성하며
해시를 역산하지 않습니다. Arduino는 한 번에 한 블록씩 계산하므로 메시지
크기만큼의 패드를 따로 저장하지 않습니다. 패킷과 응용 프로그램 버퍼는 여전히 필요합니다.

12바이트 salt에는 초(4바이트), 밀리초(2바이트), 카운터(2바이트), nonce(4바이트)가
들어갑니다. 이 값들은 비밀이 아닙니다. **공개된 랜덤 값만 해시해서는 비밀
키스트림이 되지 않습니다.** 누구나 같은 계산을 할 수 있기 때문입니다.
비밀 키가 비밀 입력을 제공하며, 같은 키와 salt를 반복하면 같은 키스트림이 생성됩니다.

‘가상 OTP’ 또는 ‘유사 OTP’는 이렇게 생성한 키스트림을 뜻하며 진짜 OTP의
정보이론적 보장을 뜻하지 않습니다. 해시는 약한 비밀에 엔트로피를 더하지 않고,
표준 SHA-256을 사용한다고 전체 구성의 안전성이 보장되지는 않습니다.
키스트림 생성 후 XOR하는 방식은
[ChaCha20](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.4)에도 있지만,
Boho의 해시 기반 구성은 별개의 설계입니다.

XOR만으로는 변조를 검출하지 못합니다. 현재 Boho 데이터 패킷은
`SHA256(K || salt12 || 평문)`의 앞 8바이트를 검증 태그로 포함합니다.
기존 `generateHMAC()`이라는 이름은 **표준 HMAC을 뜻하지 않습니다.**
응용 프로그램은 검증에 성공한 뒤에만 평문을 사용해야 합니다.

### TLS와의 관계

일반적인 인증서 기반 TLS는 사용자가 미리 비밀을 공유하지 않아도 상대를
인증하고 통신 키를 설정합니다. 응용 데이터에는 대칭키 암호화를 사용합니다.
로그인하지 않은 클라이언트도 서버를 인증할 수 있지만, 이것이 네트워크 익명성을
뜻하지는 않습니다.

작은 장치에서는 인증서 체인 처리, 신뢰 루트, 인증서 유효기간과 시각 관리,
갱신, 핸드셰이크 연산과 버퍼가 구현·운영 비용을 늘릴 수 있습니다.
이미 키를 설정할 수 있는 개발자에게는 의도한 용도에 이런 구성 일부가
불필요할 수 있습니다.

다만 TLS도 **PSK-only와 PSK+(EC)DHE**를 지원합니다. 항상 공개키 교환이나
제3자 인증서 시스템이 필요한 것은 아닙니다.
[TLS 1.3의 사전 공유 키](https://www.rfc-editor.org/rfc/rfc8446.html#section-2.2)를 참고하세요.
Boho의 목표는 Arduino와 JavaScript에서 사용할 작은 공유 키 패킷·인증 구현입니다.
모든 TLS나 표준 대칭키 구현보다 성능이 좋다는 주장은 아니며, 대상 환경에서
측정해야 합니다.

### DIY 장치에서 브라우저 앱까지

Boho는 암호화와 인증을, IOSignal은 장치·Node.js·브라우저 사이의 연결과 메시지
전달을 제공합니다. 연결 인증 정보와 종단간 데이터 키는 목적이 다릅니다.
중계 서버로부터 본문을 보호하려면 최종 송수신자만 별도의 데이터 키를 가져야 합니다.
일반 연결 암호화가 자동으로 종단간 암호화가 되지는 않으며, 라우팅 정보와
트래픽 크기는 여전히 보일 수 있습니다.

일반적인 웹 배포에서는 HTTPS가 앱 코드 전달을, WSS가 연결을 보호하고,
Boho는 응용 본문을 별도로 암호화할 수 있습니다. 앱 코드를 바꿀 수 있다면 키와
평문도 탈취할 수 있습니다. 따라서 E2E에서도 신뢰할 수 있는 단말 코드가 필요합니다.
Boho는 브라우저의 mixed content 규칙을 우회하지 않습니다.

### 현재 구현에서 알아둘 조건

- 강한 무작위 비밀을 사용하세요. `set_key()`의 SHA-256 한 번은 느린 비밀번호 KDF가 아니며, Boho가 키 배포나 교체를 대신하지 않습니다.
- JavaScript는 `crypto.getRandomValues()`를 사용하지만 Arduino는 현재 독립 패킷 nonce와 인증 요청의 클라이언트 nonce에 `micros()`를 사용합니다. `micros()`는 암호학적 난수원이 아닙니다. 재시작·장치·통신 방향을 가로지르는 키/salt 중복을 확인해야 합니다.
- 유효한 태그가 신선도를 보장하지는 않습니다. challenge 만료, 재전송 거부, 순서와 명령 실행 권한은 호출 시스템이 관리합니다.
- Boho는 표준 AEAD 구성이 아닌 자체 프로토콜입니다. SHA-256 사용만으로 TLS나 표준 AEAD와 같은 보장을 기대해서는 안 됩니다. 장기 공유 키가 나중에 유출될 때 과거 통신을 보호하는 순방향 비밀성은 제공하지 않습니다.

## 설치

이 라이브러리와 `SHA256.h`를 제공하는 의존 라이브러리 **Crypto**를 설치하세요.
로컬 개발판이나 미출시 버전은 Arduino IDE에서 라이브러리 ZIP을 설치하거나
스케치북의 `libraries` 디렉터리에 폴더를 넣으세요. 이전 헤더가 선택되지 않도록
Boho 설치본은 하나만 유지하세요.

```cpp
#include <Boho.h>
```

IOSignal은 Boho를 외부 라이브러리로 사용하며 **Boho 0.8.0 이상**이 필요합니다.
`Boho.cpp`나 `Boho.h`를 IOSignal의 `src/` 디렉터리에 복사하지 마세요.

## 빠른 시작: 데이터 암호화와 복호화

다음 독립 실행 스케치는 예제용 키를 사용합니다. 실제 사용 전에 자신의 공유
비밀로 바꾸세요.

```cpp
#include <Boho.h>

Boho boho;
const char message[] = "Hello, Boho!";
uint8_t packet[sizeof(message) - 1 + MetaSize_ENC_PACK];
uint8_t plaintext[sizeof(message) - 1];

void setup() {
  Serial.begin(115200);
  boho.set_key("replace-with-your-shared-secret");

  const uint32_t packetLen = boho.encryptPack(
      packet, message, sizeof(message) - 1);
  if (packetLen == 0) {
    Serial.println("Encryption failed");
    return;
  }

  uint32_t plaintextLen = 0;
  if (boho.decryptPack(plaintext, packet, packetLen, plaintextLen)) {
    Serial.write(plaintext, plaintextLen);
    Serial.println();
  } else {
    Serial.println("Packet rejected");
  }
}

void loop() {}
```

복호화된 바이트에는 **NUL 종료 문자가 자동으로 붙지 않습니다.** 바이너리
데이터나 `Serial.write()`에는 반환된 길이를 사용하세요. C 문자열이 필요하면
1바이트를 더 확보하고 검증 성공 후 종료 문자를 추가하세요.

## 패킷 유형과 버퍼 크기

| API | 용도 | 암호화 출력 크기 | 연결 인증 필요 여부 |
| --- | --- | --- | --- |
| `encryptPack` / `decryptPack` | 독립 데이터 패킷 (`ENC_PACK`) | 평문 + 25바이트 | 불필요; 키는 필요 |
| `encrypt_e2e` / `decrypt_e2e` | 별도 데이터 키를 사용하는 독립 패킷 | 평문 + 25바이트 | 불필요 |
| `encrypt_488` / `decrypt_488` | 인증된 연결의 통신 (`ENC_488`) | 평문 + 21바이트 | 필요 |

크기를 직접 적는 대신 `MetaSize_ENC_PACK`과 `MetaSize_ENC_488`을 사용하세요.
암호화는 패킷 길이를 반환하며 실패하면 `0`을 반환합니다. 이 API는 버퍼 용량을
인자로 받지 않으므로 호출 측이 출력 버퍼를 확보해야 합니다.

복호화에는 평문을 담을 충분한 공간을 확보하세요. 완전한 일반 패킷이 해당
헤더보다 짧지 않다면, 수신 크기에서 헤더 크기를 뺀 값이 평문 크기의 상한입니다.
메모리를 할당하기 전에 응용 프로그램의 최대 패킷 크기를 적용하세요.
출력은 성공한 경우에만 사용하세요.

### 빈 메시지와 반환값

버전 0.8.0에는 성공 여부와 평문 길이를 별도로 반환하는 오버로드가 추가되었습니다.

```cpp
bool decryptPack(void *out, const uint8_t *in, uint32_t len, uint32_t &plainLen);
bool decrypt_488(void *out, const uint8_t *in, uint32_t len, uint32_t &plainLen);
bool decrypt_e2e(void *out, const uint8_t *in, uint32_t len,
                 const char *key, uint32_t &plainLen);
```

반환값이 `true`이고 `plainLen == 0`이면 검증된 빈 메시지입니다.
기존의 길이 반환 오버로드도 사용할 수 있지만, 반환값 `0`만으로는 빈 평문과
실패를 구분할 수 없습니다. 빈 메시지를 허용한다면 새 오버로드를 사용하세요.

## 클라이언트–서버 인증

인증하기 전에 ID와 비어 있지 않은 공유 키를 설정하세요.

```cpp
boho.set_id8("device1");
boho.set_key("replace-with-your-shared-secret");
// Alternative: boho.set_id_key("device1.replace-with-your-shared-secret");
```

`set_id8()`은 최대 **8바이트**를 복사하고 기존 값의 남은 부분을 지웁니다.
`set_id_key()`에는 1~8바이트 ID, `.` 구분자, 비어 있지 않은 키가 필요합니다.
잘못된 조합을 주면 인증 상태가 초기화됩니다. 서버의 인증 정보 공급자에도 같은
ID와 키를 설정하세요.

일반적인 인증 순서는 다음과 같습니다.

1. 서버에서 완전한 `SERVER_TIME_NONCE` 패킷(13바이트)을 받습니다.
2. `auth_req(out, challenge, challengeLen)`을 호출하여 반환된 바이트를 보냅니다. 출력 버퍼에는 `MetaSize_AUTH_REQ`(45바이트)를 담을 수 있어야 합니다. 반환 길이가 0이면 보내지 마세요.
3. `AUTH_RES`를 받고 `verify_auth_res(response, responseLen)`을 호출합니다.
4. 성공하면 `isAuthorized`가 `true`가 되고 연결 통신에 `encrypt_488()`과 `decrypt_488()`을 사용할 수 있습니다.

핸드셰이크를 생략하려고 `isAuthorized = true`를 직접 설정하지 마세요.
이 교환은 양쪽에 필요한 nonce도 설정합니다.

지연·수동 로그인에서는 `setClientTimeToServerTime(challenge, len)`이 검증된
challenge를 보관합니다. 인증 정보를 설정한 뒤 `auth_req(out)`이 이를 사용할 수
있습니다. challenge나 키가 없으면 0을 반환합니다. 보관한 challenge는 해당 서버
연결에 속하므로 다시 연결하면 새로 받아야 합니다.

`clearAuth()`는 ID, 키, nonce, 보관한 challenge와 인증 플래그를 지웁니다.
다음 인증 교환 전에 인증 정보를 다시 설정하세요.

## 종단간 암호화와 IOSignal

`encrypt_e2e(out, data, len, key)`는 지정한 데이터 키로 `ENC_PACK`을 만들고
원래 연결 키를 복원합니다. 수신자는 같은 데이터 키로
`decrypt_e2e(out, packet, packetLen, key, plainLen)`을 사용합니다.
이 독립적인 연산에는 인증된 연결이 필요하지 않습니다.

IOSignal은 연결 키로 암호화한 라우팅 헤더 뒤에 독립 암호화 본문을 붙이는
`ENC_E2E` 형식을 추가합니다. `decrypt_488()`은 이 형식을 받아 라우팅 헤더만
검증합니다. 최종 수신자는 `decrypt_e2e()`로 본문을 별도 검증해야 합니다.
일반 `ENC_488` 패킷은 선언한 길이와 정확히 일치해야 하지만, `ENC_E2E`에는
뒤따르는 본문이 허용됩니다.

## 시간과 메모리

- `setTime(unixSeconds, milliseconds)`는 로컬 UTC 시계를 설정합니다.
- `refreshTime()`은 `millis()`로 시간을 진행시키며 타이머 순환도 처리합니다.
- `getUnixTime()`과 `getMilTime()`은 마지막 갱신 값을 반환합니다. 암호화 연산 밖에서 시간을 읽을 때는 `refreshTime()`을 호출하세요.
- 인증 과정과 `setClientTimeToServerTime()`은 서버 challenge로 시각을 동기화할 수 있습니다.
- 패킷 태그 생성은 키/salt와 페이로드를 점진적으로 해시하므로 페이로드 크기에 비례하는 임시 할당을 피합니다.
- `dynamic_alloc()`은 ESP32에서 PSRAM을 감지하면 사용하고, 그 외에는 `malloc()`을 사용합니다. 할당 결과를 항상 확인하고 보드에 맞게 버퍼 크기를 정하세요.

## 호환성과 보안 범위

버전 0.8.0은 기존 패킷 형식을 유지하면서 입력 검증, ID 파싱 수정, 수동 인증,
시계 수정과 성공 여부를 확인하는 복호화 API를 추가합니다. 구현은 정수의
네이티브 바이트 순서를 사용하므로 기존 JS 호환 패킷 형식에는 little-endian
대상이 필요합니다.

Boho는 SHA-256 기반 자체 구성을 사용합니다. 기존 `generateHMAC()` 이름은
프로토콜 태그를 뜻하며 표준 HMAC이 아닙니다. TLS나 표준 AEAD의 보장을 제공하지
않습니다. 키 배포, challenge 만료와 재전송 거부는 응용 프로그램이 담당합니다.
패킷 검증 성공만으로 신선도를 보장하지 않습니다. E2E로 중계 서버로부터 본문을
보호하려면 그 서버에 데이터 키를 제공하지 마세요.

호스트 테스트는 잘못된 입력과 Arduino·JavaScript 상호 운용성을 검사하며,
인증과 일반/E2E 통신을 포함합니다. 보드 빌드, SRAM 검사나 장치 통신 테스트를
대체하지는 않습니다.

## 예제와 관련 프로젝트

- [일반 암호화](examples/Boho-general-encryption/Boho-general-encryption.ino)
- [Unix 시각](examples/Boho-unix-time/Boho-unix-time.ino)
- [JavaScript용 Boho](https://github.com/remocons/boho)
- [Arduino용 IOSignal](https://github.com/remocons/iosignal-arduino)

## 라이선스

[MIT](LICENSE)

#include <QApplication>
#include "login_window.h"

// class LoginHandler : public MessageHandler<LoginHandler> {
// public:
//     static constexpr auto Type = MessageType::Login;
//
//     void handle(QJsonObject json) {
//         if (json["id"] == "loginRsp") {
//             // 处理登录响应逻辑
//         } else if (json["id"] == "verifyRsp") {
//             // 处理验证响应逻辑
//         }
//         // 错误处理...
//     }
// };
#include <QTextCodec>
int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    LoginWindow w;
    w.show();

    return QApplication::exec();
}

#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QMouseEvent>
#include <QApplication>
#include "tcpmgr.h"
class LoginWindow : public QWidget {
    Q_OBJECT

public:
    explicit LoginWindow(QWidget *parent = nullptr)
        : QWidget(parent) {
        // 窗口基础设置（网页1关键步骤）
        setFixedSize(400, 300); // 固定尺寸
        setupUI();
        applyStyle(); // 应用样式
        m_tcpManager = new TcpManager(this);
        m_tcpManager->registerHandler<LoginHandler>();
        connect(m_tcpManager, &TcpManager::connected, this, [] {
            qDebug() << "conencted is success";
        });
        m_tcpManager->m_handler->waitConnect(QHostAddress::LocalHost, 5555);
    }

protected:
    // 实现窗口拖动（网页1鼠标事件处理）
    void mousePressEvent(QMouseEvent *event) override {
        if (event->button() == Qt::LeftButton) {
            m_dragPosition = event->globalPos() - frameGeometry().topLeft();
            event->accept();
        }
    }

    void mouseMoveEvent(QMouseEvent *event) override {
        if (event->buttons() & Qt::LeftButton) {
            move(event->globalPos() - m_dragPosition);
            event->accept();
        }
    }

private:
    void setupUI() {
        // 主布局（垂直方向）
        QVBoxLayout *mainLayout = new QVBoxLayout(this);

        // 标题栏
        QLabel *titleLabel = new QLabel("用户登录", this);
        titleLabel->setAlignment(Qt::AlignCenter);

        // 账号输入区
        QHBoxLayout *userLayout = new QHBoxLayout;
        QLabel *userIcon = new QLabel("👤", this);
        m_userEdit = new QLineEdit(this);
        userLayout->addWidget(userIcon);
        userLayout->addWidget(m_userEdit);

        // 密码输入区
        QHBoxLayout *passLayout = new QHBoxLayout;
        QLabel *passIcon = new QLabel("🔒", this);
        m_passEdit = new QLineEdit(this);
        m_passEdit->setEchoMode(QLineEdit::Password);
        passLayout->addWidget(passIcon);
        passLayout->addWidget(m_passEdit);

        // 登录按钮
        QPushButton *loginBtn = new QPushButton("登 录", this);
        connect(loginBtn, &QPushButton::clicked, this, &LoginWindow::onLogin);

        // 添加控件到主布局
        mainLayout->addWidget(titleLabel);
        mainLayout->addSpacing(30);
        mainLayout->addLayout(userLayout);
        mainLayout->addLayout(passLayout);
        mainLayout->addSpacing(20);
        mainLayout->addWidget(loginBtn);
    }

    void applyStyle() {
        // 窗口样式（网页1的QSS实现思路）
        setStyleSheet(R"(
            QWidget {
                background: #F5F5F5;
                border-radius: 8px;
            }
            QLabel {
                font-size: 18px;
                color: #333;
            }
            QLineEdit {
                padding: 8px 12px;
                border: 1px solid #DDD;
                border-radius: 4px;
                min-width: 200px;
            }
            QPushButton {
                background: #0084FF;
                color: white;
                padding: 10px 20px;
                border-radius: 4px;
                font-size: 16px;
            }
            QPushButton:hover {
                background: #0073E6;
            }
        )");
    }

    class LoginHandler : public MessageHandler<LoginHandler> {
    public:
        static constexpr auto Type = MessageType::Login; // 登录模块的起始类型

        static void handle(QJsonObject json) {
            // 通过 MessageType 来判断处理不同的消息
            switch (int msgId = json["id"].toInt(); static_cast<MessageType>(msgId)) {
                case MessageType::LoginRsp:
                    qDebug() << "处理登录响应 (LoginRsp):" << json;
                    break;
                default:
                    qWarning() << "没有匹配的处理程序，ID:" << msgId;
                    break;
            }
        }
    };

private slots:
    void onLogin() const {
        // 登录逻辑
        qDebug() << "Login attempt:"
                << m_userEdit->text()
                << m_passEdit->text();

        // 构造登录请求
        QJsonObject loginReq{
            {"id", static_cast<int>(MessageType::LoginReq)}, // 使用枚举ID
            {
                "data", QJsonObject{
                    {"user", m_userEdit->text()},
                    {"pass", m_passEdit->text()},
                    {"timestamp", QDateTime::currentSecsSinceEpoch()}
                }
            }
        };

        // 发送请求
        m_tcpManager->sendMessage(loginReq);

        qDebug() << "Login request sent:" << loginReq;

        // 等待服务器的回应（可以适当调整时间，或添加超时机制）
        // if (!m_tcpManager.m_handler->m_socket->waitForReadyRead(1000)) {
        //     qWarning() << "read timeout error: " << m_tcpManager.m_handler->m_socket->errorString();
        // }
    }

private:
    QLineEdit *m_userEdit;
    QLineEdit *m_passEdit;
    QPoint m_dragPosition;
    static inline TcpManager *m_tcpManager{};
};

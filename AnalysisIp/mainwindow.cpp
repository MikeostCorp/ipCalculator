#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QMessageBox>
#include <QMouseEvent>
#include "QPixmap"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle("ip-Analysis");
    ui->lineEdit_1->setInputMask("000.000.000.000 ;_");
    this->setWindowFlag( Qt::MSWindowsFixedSizeDialogHint, true);
    this->setWindowFlag(Qt::FramelessWindowHint, true);
    this->setWindowIcon(QIcon(":/image/icon.png"));

    int w = ui->headImage->width();
    int h = ui->headImage->height();
    QPixmap picture1(":/image/icon.png");
    ui->headImage->setPixmap(picture1.scaled(w,h, Qt::KeepAspectRatio));

    ui->label_3->setText("Адрес:   93.78.30.214   01011101.01001110.00011110.11010110");
}

MainWindow::~MainWindow()
{
    delete ui;
}

QString inBin(QString ip) {
    QString ipOctetStr;
    int ipOctetInt;
    QString res;

    for(int i = 0; i < ip.size(); ++i){
        if(ip[i] != '.' && ip[i] != ' '){
            ipOctetStr += ip[i];
            continue;
        }

        ipOctetInt = ipOctetStr.toInt();
        ipOctetStr = NULL;
        while(ipOctetInt){
            ipOctetStr += QString::number(ipOctetInt % 2);
            ipOctetInt /= 2;
        }

        while(std::size(ipOctetStr) < 8){
            ipOctetStr += '0';
        }

        std::reverse(ipOctetStr.begin(), ipOctetStr.end());
        res += ipOctetStr;
        if(res.size() < 27) res += '.';
        ipOctetStr = NULL;
        ipOctetInt = 0;
    }

    return res;
}

QString inDec(QString ip) {
    QString ipOctetStr;
        QString res;

        for(int i = 0; i < 4; ++i){

            int ipOctetInt = 0;
            for(int j = i * 8 + i, exp = 7; j <= (i + 1) * 8 + i - 1; ++j){
                    ip[j].digitValue() == 1 ? ipOctetInt += pow(2, exp--): exp--;
            }
            res += QString::number(ipOctetInt);
            if(i < 3) res += '.';
        }

        return res;
}

void MainWindow::on_pushButton_clicked()
{
    QString fullIp = ui->lineEdit_1->text();
    QString ipClass;
    QString ipRes;
    QString maskNetworkDefault;
    QString maxNumberNetwork;
    QString maxNumberNode;
    QString numberBitsInAdress;
    QString Netmask;
    QString Network, Broadcast, Hostmin, Hostmax, Wildcard;
    int indexComboBox, octet[4] = {0, 0, 0, 0}, octetip[4] = {0, 0, 0, 0};
    int cor = 0, hosts;

    //IP
    for(int i = 0, j = 0; i < std::size(fullIp); ++i) {
        if(fullIp[i] != '.' && fullIp[i] != ' ') {
            ipRes += fullIp[i];
        }
        else {
            octetip[j] = ipRes.toInt();
            j++;
            ipRes = NULL;
        }
    }

    //условие на проверку введения ip адресса
    if(std::size(fullIp) > 6 && octetip[0] < 255 && octetip[0] > 0 && octetip[1] < 256 && octetip[1] > 0 && octetip[2] < 256 && octetip[2] > 0 && octetip[3] < 256 && octetip[3] > 0){

        //first hren
        if(ui->radioButton->isChecked()) {

            // Преобразование первой части ip-адреса в бинарный вид
            while(octetip[0] != 0){
                ipRes += QString::number(octetip[0] % 2);
                octetip[0] /= 2;
            }

            // Добавление недостающих до 1 байта нулей
            while(std::size(ipRes) < 8)
                ipRes += '0';

            // Преобразование бинарного кода в нормальный вид
            std::reverse(ipRes.begin(), ipRes.end());

            // Определение характеристик адреса
            if(ipRes[0] == '0') {
                ipClass = 'A';
                maskNetworkDefault = "255.0.0.0";
                numberBitsInAdress = "8/24";
                maxNumberNetwork = "2^7 - 2";
                maxNumberNode = "2^24 - 2";
            }
            else if(ipRes[0] == '1' && ipRes[1] == '0') {
                ipClass = 'B';
                maskNetworkDefault = "255.255.0.0";
                numberBitsInAdress = "16/16";
                maxNumberNetwork = "2^14";
                maxNumberNode = "2^16 - 2";
            }
            else if(ipRes[0] == '1' && ipRes[1] == '1' && ipRes[2] == '0') {
                ipClass = 'C';
                maskNetworkDefault = "255.255.255.0";
                numberBitsInAdress = "8/24";
                maxNumberNetwork = "2^21";
                maxNumberNode = "2^8 - 2";
            }
            else if(ipRes[0] == '1' && ipRes[1] == '1' && ipRes[2] == '1' && ipRes[3] == '0') {
                ipClass = 'D';
                maskNetworkDefault = "-";
                numberBitsInAdress = "-";
                maxNumberNetwork = "-";
                maxNumberNode = "-";
            }
            else if(ipRes[0] == '1' && ipRes[1] == '1' && ipRes[2] == '1' && ipRes[3] == '1') {
                ipClass = 'E';
                maskNetworkDefault = "-";
                numberBitsInAdress = "-";
                maxNumberNetwork = "-";
                maxNumberNode = "-";
            }

            ui->label_3->setText("ip-адрес (бинарный вид): " + ipRes
                                 + "\nКласс ip-адреса: " + ipClass
                                 + "\nМаска подсети по умолчанию: " + maskNetworkDefault
                                 + "\nКол-во бит в адресе сети/ узле: " + numberBitsInAdress
                                 + "\nМаксимальное кол-во сетей: " + maxNumberNetwork
                                 + "\nМаксимальное кол-во узлов: " + maxNumberNode);
            }

        //second hren
        else if(ui->radioButton_2->isChecked()) {
                indexComboBox = ui->comboBox->currentIndex();

                //Netmask
                for(int i = 1; i < 36; i++) {
                    if(i % 9 == 0) {
                        Netmask = Netmask + '.';
                        cor++;
                    }
                    else if(i <= indexComboBox + cor) {
                        Netmask = Netmask + '1';
                    }
                    else Netmask = Netmask + '0';
                }

                //Hosts
                hosts = pow(2, (32 - indexComboBox));

                //Network
                fullIp = inBin(fullIp);
                for(int i = 0; i < Netmask.size(); ++i) {
                    if(fullIp[i] != '.') {
                        if(fullIp[i] == '0' && Netmask[i] == '0') {
                            Network = Network + '0';
                        }
                        else if (fullIp[i] == '1' && Netmask[i] == '0') {
                            Network = Network + '0';
                        }
                        else if (fullIp[i] == '0' && Netmask[i] == '1') {
                            Network = Network + '0';
                        }
                        else Network = Network + '1';
                    }
                    else Network = Network + '.';
                }

                //Broadcast
                Broadcast = Network;
                for(int i = 0, cor = 0; i < Broadcast.size(); ++i) {
                    if(i >= indexComboBox + cor && Broadcast[i] != '.') {
                        if(Broadcast[i] == '0') {
                            Broadcast[i] = '1';
                        } else Broadcast[i] = '0';
                    }
                    else if(Broadcast[i] == '.') cor++;
                }

                //Hostmin
                Hostmin = Network;
                if(Hostmin[Hostmin.size()-1] == '1') {
                    Hostmin[Hostmin.size()-1] = '0';
                }
                else Hostmin[Hostmin.size()-1] = '1';

                //Hostmax
                Hostmax = Broadcast;
                if(Hostmax[Hostmax.size()-1] == '1') {
                    Hostmax[Hostmax.size()-1] = '0';
                }
                else Hostmax[Hostmax.size()-1] = '1';

                //Wildcard
                for(int i = 0 ;i < 4; i++) {
                      Wildcard += QString::number(255 - octet[i]);
                      if(i != 3)
                        Wildcard += '.';
                }

                QMessageBox::critical(this,"Ошибка!", inDec(fullIp));
        }
        else QMessageBox::critical(this,"Ошибка!","Лох печальный");
    }
    else {
        QMessageBox::critical(this,"Ошибка!","Проверьте правильность ввода ip-адреса!"
                                   "\n\nДиапазон адресов: 1.0.0.0 - 254.255.255.255");
    }
}

void MainWindow::mousePressEvent(QMouseEvent *event)
{
    if(event->button() == Qt::LeftButton)
    {
        oldPos = event->pos();
        event->accept();
    }
}


void MainWindow::mouseMoveEvent(QMouseEvent* event)
{
   if(oldPos.x() < 550 and oldPos.y() < 25){ // проверка нажатия только по тайтл бару

   QPoint delta = event->globalPos() - oldPos;
   move(delta);
   event->accept();
    }
}

void MainWindow::on_pushButton_4_clicked()
{
    ui->label_3->clear();
    ui->lineEdit_1->clear();
}

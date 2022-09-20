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
}

MainWindow::~MainWindow()
{
    delete ui;
}

QString inBin(QString ip) {
    QString ipOctetStr;
    int ipOctetInt;
    QString res;
    QStringList ipOctet = ip.split('.');

    for(int i = 0; i < 4; ++i){

        ipOctetInt = (ipOctet.at(i)).toInt();
        ipOctetStr = NULL;
        while(ipOctetInt > 0){
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
    int indexComboBox, octetip[4] = {0, 0, 0, 0};
    int cor = 0;
    long long hosts;

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
    if(std::size(fullIp) > 6 && octetip[0] < 255 && octetip[0] > 0
                             && octetip[1] < 256 && octetip[1] > 0
                             && octetip[2] < 256 && octetip[2] > 0
                             && octetip[3] < 256 && octetip[3] > 0){

        //first hren
        if(ui->radioButton->isChecked()) {
            //Очистка экранов
            ui->label_3->clear();
            ui->label_11->clear();

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
                if(indexComboBox != 32) {
                    hosts = pow(2, (32 - indexComboBox));
                    hosts -= 2;
                } else hosts = 0;

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
                Netmask = inDec(Netmask);
                QString cool;
                for(int i = 0, cor = 0; i < Netmask.size(); i++) {
                    if(Netmask[i] != '.') {
                        cool += Netmask[i];
                    }
                    else {
                        Wildcard += QString::number(255 - cool.toInt()) + '.';
                        cool = NULL;
                        cor++;     
                    }

                    if(i == Netmask.size()-1 && cor == 3)
                        Wildcard += QString::number(255 - cool.toInt());
                }

                ui->label_3->setText("Адрес    :\t" + inDec(fullIp)
                                     + "\nBitmask  :\t" + QString::number(indexComboBox)
                                     + "\nNetmask  :\t" + Netmask
                                     + "\nWildcard :\t" + Wildcard
                                     + "\nNetwork  :\t" + inDec(Network)
                                     + "\nBroadcast:\t" + inDec(Broadcast)
                                     + "\nHostmin  :\t" + inDec(Hostmin)
                                     + "\nHostmax  :\t" + inDec(Hostmax)
                                     + "\nHosts    :\t" + QString::number(hosts));

                ui->label_11->setText(fullIp
                                      + "\n"
                                      + "\n" + inBin(Netmask)
                                      + "\n" + inBin(Wildcard)
                                      + "\n" + Network
                                      + "\n" + Broadcast
                                      + "\n" + Hostmin
                                      + "\n" + Hostmax
                                      + "\n");
        }
        else QMessageBox::critical(this,"Ошибка!","Выберите нотацию");
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
    ui->label_11->clear();
    ui->label_3->clear();
    ui->lineEdit_1->clear();
}

void MainWindow::on_radioButton_clicked()
{
        ui->comboBox->setEnabled(false);
        //ui->comboBox->setStyleSheet("QComboBox{font: 700 10pt ;color: rgb(236, 236, 236); background-color: rgb(52, 52, 54); border-style: solid; border-width: 1px; border-radius: 12px; border-color: rgb(52, 52, 54); padding-left: 9px; }  QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: top right;width: 15px; border-left-width: 1px;border-left-color: darkgray; border-left-style: solid;  border-top-right-radius: 3px; border-bottom-right-radius: 3px; }QComboBox QListView{ background-color:rgb(62,62,64);border: 1px solid rgb(62,62,64);color: rgb(236, 236, 236);border-width: 2px;border-radius: 12px; }QComboBox QAbstractItemView {border: 1px  solid rgb(62,62,64);}");
}


void MainWindow::on_radioButton_2_clicked()
{
    ui->comboBox->setEnabled(true);
}


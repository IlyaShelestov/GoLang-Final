package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	CONN_PORT      = ":9090"
	CONN_TYPE      = "tcp"
	ADMIN_PASSWORD = "admin123"
)

var (
	hexKey           = "d282a02a534d7be5b777b592227bdc3fa1ee8bedf853e129d17db9976817adab"
	encryptionKey, _ = hex.DecodeString(hexKey)
	clients          = make(map[net.Conn]string)
	addr             = make(map[net.Conn]string)
	mutex            sync.Mutex
	bannedIPs        = make(map[string]bool)
	admins           = make(map[string]bool)
	historyLog       = "history.log"
	tasks            = make(map[string]Task)
	taskIDCounter    int
	logs             []string
)

type Task struct {
	ID          string
	Description string
	Owner       string
}

func encryptMessage(plainText string) (string, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func decryptMessage(cipherText string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("cipherText too short")
	}

	nonce, cipherTextBytes := data[:nonceSize], data[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherTextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

func handleConnection(conn net.Conn) {
	nickname := "Anonymous"
	clientIP := conn.RemoteAddr().String()

	if bannedIPs[clientIP] {
		encryptedMessage, _ := encryptMessage("You are banned from this server.\n")
		conn.Write([]byte(encryptedMessage + "\n"))
		conn.Close()
		return
	}

	mutex.Lock()
	clients[conn] = nickname
	addr[conn] = clientIP
	mutex.Unlock()

	defer func() {
		mutex.Lock()
		delete(clients, conn)
		delete(addr, conn)
		mutex.Unlock()
		conn.Close()
	}()

	logFile, err := os.OpenFile(historyLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Error opening history log file:", err)
		return
	}
	defer logFile.Close()

	log.Printf("Client %s (%s) connected.", addr[conn], nickname)
	logs = append(logs, fmt.Sprintf("Client %s (%s) connected.", addr[conn], nickname))

	for {
		netData, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			log.Printf("Client %s (%s) disconnected.", addr[conn], nickname)
			logs = append(logs, fmt.Sprintf("Client %s (%s) disconnected.", addr[conn], nickname))
			broadcastMessage(fmt.Sprintf("%s disconnected from the chat!\n", nickname), conn)
			break
		}

		decryptedData, err := decryptMessage(strings.TrimSpace(netData))
		if err != nil {
			encryptedMessage, _ := encryptMessage("Error decrypting message.\n")
			conn.Write([]byte(encryptedMessage + "\n"))
			continue
		}

		handleCommands(conn, &nickname, decryptedData, logFile)
	}
}

func handleCommands(conn net.Conn, nickname *string, message string, logFile *os.File) {
	if strings.HasPrefix(message, "/quit") {
		encryptedMessage, _ := encryptMessage("Goodbye!\n")
		conn.Write([]byte(encryptedMessage + "\n"))
		conn.Close()
	} else if strings.HasPrefix(message, "/history") {
		sendHistory(conn)
	} else if strings.HasPrefix(message, "/help") {
		sendHelp(conn)
	} else if strings.HasPrefix(message, "/nickname") {
		parts := strings.SplitN(message, " ", 2)
		if len(parts) == 2 {
			changeNickname(conn, nickname, parts[1])
		}
	} else if strings.HasPrefix(message, "/users") {
		sendUsersList(conn)
	} else if strings.HasPrefix(message, "/bot task") {
		handleBotTaskCommands(conn, nickname, message)
	} else if strings.HasPrefix(message, "/admin") {
		handleAdminCommands(conn, message)
	} else if strings.HasPrefix(message, "/bot timer") {
		parts := strings.SplitN(message, " ", 3)
		if len(parts) == 3 {
			timerDuration, err := time.ParseDuration(parts[2] + "m")
			if err != nil {
				encryptedMessage, _ := encryptMessage("Invalid timer duration.\n")
				conn.Write([]byte(encryptedMessage + "\n"))
				return
			}
			setBotTimer(conn, *nickname, timerDuration)
		}
	} else {
		logMessage(*nickname, message, logFile)
		response := fmt.Sprintf("%s: %s\n", *nickname, message)
		broadcastMessage(response, conn)
	}

	currentTime := time.Now().Format(time.RFC1123)
	logEntry := fmt.Sprintf("%s: %s - %s\n", currentTime, addr[conn], message)
	logs = append(logs, logEntry)
}

func handleBotTaskCommands(conn net.Conn, nickname *string, message string) {
	parts := strings.SplitN(message, " ", 4)
	if len(parts) < 3 {
		encryptedMessage, _ := encryptMessage("Invalid /bot task command.\n")
		conn.Write([]byte(encryptedMessage + "\n"))
		return
	}

	action := parts[2]
	switch action {
	case "add":
		if len(parts) == 4 {
			addTask(conn, *nickname, parts[3])
		} else {
			encryptedMessage, _ := encryptMessage("Usage: /bot task add <description>\n")
			conn.Write([]byte(encryptedMessage + "\n"))
		}
	case "list":
		listTasks(conn)
	case "delete":
		if len(parts) == 4 {
			deleteTask(conn, parts[3])
		} else {
			encryptedMessage, _ := encryptMessage("Usage: /bot task delete <task_id>\n")
			conn.Write([]byte(encryptedMessage + "\n"))
		}
	default:
		encryptedMessage, _ := encryptMessage("Unknown /bot task action.\n")
		conn.Write([]byte(encryptedMessage + "\n"))
	}
}

func handleAdminCommands(conn net.Conn, message string) {
	parts := strings.SplitN(message, " ", 3)
	clientIP := conn.RemoteAddr().String()

	if len(parts) < 2 {
		encryptedMessage, _ := encryptMessage("Invalid admin command.\n")
		conn.Write([]byte(encryptedMessage + "\n"))
		return
	}

	if parts[1] == ADMIN_PASSWORD {
		admins[clientIP] = true
		encryptedMessage, _ := encryptMessage("Admin access granted.\n")
		conn.Write([]byte(encryptedMessage + "\n"))
		return
	}

	if !admins[clientIP] {
		encryptedMessage, _ := encryptMessage("You are not an admin.\n")
		conn.Write([]byte(encryptedMessage + "\n"))
		return
	}

	switch parts[1] {
	case "quit":
		delete(admins, clientIP)
		encryptedMessage, _ := encryptMessage("Admin access revoked.\n")
		conn.Write([]byte(encryptedMessage + "\n"))
	case "ban":
		if len(parts) == 3 {
			banUser(conn, parts[2])
		} else {
			encryptedMessage, _ := encryptMessage("Usage: /admin ban <nickname>\n")
			conn.Write([]byte(encryptedMessage + "\n"))
		}
	case "kick":
		if len(parts) == 3 {
			kickUser(conn, parts[2])
		} else {
			encryptedMessage, _ := encryptMessage("Usage: /admin kick <nickname>\n")
			conn.Write([]byte(encryptedMessage + "\n"))
		}
	case "logs":
		sendLogs(conn)
	default:
		encryptedMessage, _ := encryptMessage("Unknown admin command.\n")
		conn.Write([]byte(encryptedMessage + "\n"))
	}

	currentTime := time.Now().Format(time.RFC1123)
	logEntry := fmt.Sprintf("%s: %s - %s\n", currentTime, clientIP, message)
	logs = append(logs, logEntry)
}

func sendHelp(conn net.Conn) {
	commandsList := []string{
		"/help - Prints all possible commands",
		"/nickname <name> - Change your nickname",
		"/users - Lists all connected users",
		"/bot task add <description> - Add a new task",
		"/bot task list - List all tasks",
		"/bot task delete <task_id> - Delete a task",
		"/bot timer <minutes> - Set a timer in minutes",
		"/admin <password> - Gain admin access",
		"/admin ban <nickname> - Ban a user by nickname",
		"/admin kick <nickname> - Kick a user by nickname",
		"/admin logs - Show all logs",
		"/history - Show chat history",
		"/quit - Disconnect from the server",
	}
	for _, command := range commandsList {
		encryptedCommand, _ := encryptMessage(command + "\n")
		conn.Write([]byte(encryptedCommand + "\n"))
		time.Sleep(10 * time.Millisecond)
	}
}

func sendUsersList(conn net.Conn) {
	mutex.Lock()
	defer mutex.Unlock()

	var users []string
	for _, nickname := range clients {
		users = append(users, nickname)
	}

	usersList := strings.Join(users, ", ")
	message := fmt.Sprintf("Connected users: %s\n", usersList)
	encryptedMessage, _ := encryptMessage(message)
	conn.Write([]byte(encryptedMessage + "\n"))
}

func changeNickname(conn net.Conn, nickname *string, newNickname string) {
	oldNickname := *nickname
	*nickname = newNickname

	mutex.Lock()
	clients[conn] = newNickname
	mutex.Unlock()

	encryptedMessage, _ := encryptMessage(fmt.Sprintf("Nickname changed to %s\n", newNickname))
	conn.Write([]byte(encryptedMessage + "\n"))

	log.Printf("Client %s (%s) changed nickname to %s.", addr[conn], oldNickname, newNickname)
	logs = append(logs, fmt.Sprintf("Client %s (%s) changed nickname to %s.", addr[conn], oldNickname, newNickname))
	broadcastMessage(fmt.Sprintf("'%s' changed nickname to '%s'\n", oldNickname, newNickname), conn)
}

func sendHistory(conn net.Conn) {
	file, err := os.Open(historyLog)
	if err != nil {
		encryptedMessage, _ := encryptMessage("Error reading history.\n")
		conn.Write([]byte(encryptedMessage + "\n"))
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		message := scanner.Text() + "\n"
		encryptedMessage, err := encryptMessage(message)
		if err != nil {
			log.Printf("Error encrypting history message: %s", err)
			continue
		}
		conn.Write([]byte(encryptedMessage + "\n"))
		time.Sleep(10 * time.Millisecond)
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading from history file: %s", err)
		encryptedMessage, _ := encryptMessage("Error occurred while reading history.\n")
		conn.Write([]byte(encryptedMessage + "\n"))
	}
}

func logMessage(nickname string, message string, logFile *os.File) {
	currentTime := time.Now().Format(time.RFC1123)
	logEntry := fmt.Sprintf("%s: %s - %s\n", currentTime, nickname, message)
	logFile.WriteString(logEntry)
}

func broadcastMessage(message string, sender net.Conn) {
	mutex.Lock()
	defer mutex.Unlock()
	for conn := range clients {
		if conn != sender {
			encryptedMessage, err := encryptMessage(message)
			if err != nil {
				fmt.Println("Error encrypting message:", err)
				continue
			}
			conn.Write([]byte(encryptedMessage + "\n"))
		}
	}
}

func addTask(conn net.Conn, owner, description string) {
	mutex.Lock()
	defer mutex.Unlock()

	taskIDCounter++
	taskID := fmt.Sprintf("%d", taskIDCounter)
	tasks[taskID] = Task{ID: taskID, Description: description, Owner: owner}

	encryptedMessage, _ := encryptMessage(fmt.Sprintf("Task added with ID %s\n", taskID))
	conn.Write([]byte(encryptedMessage + "\n"))
}

func listTasks(conn net.Conn) {
	mutex.Lock()
	defer mutex.Unlock()

	var taskDescriptions []string
	for _, task := range tasks {
		taskDescriptions = append(taskDescriptions, fmt.Sprintf("ID: %s, Owner: %s, Description: %s", task.ID, task.Owner, task.Description))
	}

	if len(taskDescriptions) == 0 {
		encryptedMessage, _ := encryptMessage("No tasks found.\n")
		conn.Write([]byte(encryptedMessage + "\n"))
	} else {
		for _, description := range taskDescriptions {
			encryptedDescription, _ := encryptMessage(description + "\n")
			conn.Write([]byte(encryptedDescription + "\n"))
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func deleteTask(conn net.Conn, taskID string) {
	mutex.Lock()
	defer mutex.Unlock()

	if _, ok := tasks[taskID]; ok {
		delete(tasks, taskID)
		encryptedMessage, _ := encryptMessage("Task deleted successfully.\n")
		conn.Write([]byte(encryptedMessage + "\n"))
	} else {
		encryptedMessage, _ := encryptMessage("Task not found.\n")
		conn.Write([]byte(encryptedMessage + "\n"))
	}
}

func banUser(conn net.Conn, nickname string) {
	mutex.Lock()
	defer mutex.Unlock()

	for clientConn, clientNickname := range clients {
		if clientNickname == nickname {
			clientIP := clientConn.RemoteAddr().String()
			bannedIPs[clientIP] = true
			encryptedMessage, _ := encryptMessage("You have been banned from the server.\n")
			clientConn.Write([]byte(encryptedMessage + "\n"))
			clientConn.Close()
			encryptedMessage, _ = encryptMessage(fmt.Sprintf("User %s banned successfully.\n", nickname))
			conn.Write([]byte(encryptedMessage + "\n"))
			return
		}
	}

	encryptedMessage, _ := encryptMessage(fmt.Sprintf("User %s not found.\n", nickname))
	conn.Write([]byte(encryptedMessage + "\n"))
}

func kickUser(conn net.Conn, nickname string) {
	mutex.Lock()
	defer mutex.Unlock()

	for clientConn, clientNickname := range clients {
		if clientNickname == nickname {
			encryptedMessage, _ := encryptMessage("You have been kicked from the server.\n")
			clientConn.Write([]byte(encryptedMessage + "\n"))
			clientConn.Close()
			encryptedMessage, _ = encryptMessage(fmt.Sprintf("User %s kicked successfully.\n", nickname))
			conn.Write([]byte(encryptedMessage + "\n"))
			return
		}
	}

	encryptedMessage, _ := encryptMessage(fmt.Sprintf("User %s not found.\n", nickname))
	conn.Write([]byte(encryptedMessage + "\n"))
}

func sendLogs(conn net.Conn) {
	mutex.Lock()
	defer mutex.Unlock()

	for _, logEntry := range logs {
		encryptedLogEntry, _ := encryptMessage(logEntry + "\n")
		conn.Write([]byte(encryptedLogEntry + "\n"))
		time.Sleep(10 * time.Millisecond)
	}
}

func setBotTimer(conn net.Conn, owner string, duration time.Duration) {
	encryptedMessage, _ := encryptMessage(fmt.Sprintf("Timer set for %v minutes.\n", duration.Minutes()))
	conn.Write([]byte(encryptedMessage + "\n"))

	go func() {
		time.Sleep(duration)
		message := fmt.Sprintf("Timer set by %s has ended.\n", owner)
		broadcastMessage(message, nil)
	}()
}

func main() {
	listener, err := net.Listen(CONN_TYPE, CONN_PORT)
	if err != nil {
		log.Fatal("Error starting TCP server:", err)
	}
	defer listener.Close()
	log.Println("Server listening on", CONN_PORT)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}
		go handleConnection(conn)
	}
}

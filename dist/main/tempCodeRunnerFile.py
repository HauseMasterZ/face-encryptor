def detectFace():
    new_window = tk.Toplevel(root)
    new_window.title("Train Model")
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

    video_label = tk.Label(new_window)
    video_label.pack()
    video_capture = cv2.VideoCapture(0)
    
    def update_new_frame():
        ret, frame = video_capture.read()  # Read frame from the camera
        if ret:
            small_frame = cv2.resize(frame, (0, 0), fx=0.5, fy=0.5)
            gray = cv2.cvtColor(small_frame, cv2.COLOR_BGR2GRAY)
            faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))
            for (x, y, w, h) in faces:
                # Scale the face coordinates back to the original frame size
                x *= 2
                y *= 2
                w *= 2
                h *= 2
                cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 0, 255), 2)
            # Display the frame in the new window
            image = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            image = Image.fromarray(image)
            photo = ImageTk.PhotoImage(image)
            video_label.config(image=photo)
            video_label.image = photo
        video_label.after(30, update_new_frame) # Call after 30ms

    update_new_frame()
    video_capture.release()
    cv2.destroyAllWindows()
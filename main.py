from capture.engine import CaptureEngine


def main():
    engine = CaptureEngine()

    try:
        for packet in engine.start():
            print(packet)

    except NotImplementedError as error:
        print(error)


if __name__ == "__main__":
    main()